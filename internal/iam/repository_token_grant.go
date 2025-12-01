package iam

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/lib/pq"
)

type tempGrantTuple struct {
	AppTokenId            string
	AppTokenScopeId       string
	AppTokenParentScopeId string
	GrantScopeId          string
	Grant                 string
}
type tempGrantTuples []tempGrantTuple

// grantsForTokenResults represents the raw results from the grants for token queries
type grantsForTokenResult struct {
	PermissionId      string
	Description       string
	CreateTime        string
	GrantThisScope    bool
	GrantScope        string
	AppTokenId        string
	CanonicalGrants   []string
	ActiveGrantScopes []string
}

// GrantsForToken retrieves all grants for the given app token id and resource types within the given request scope id.
// Use WithRecursive option to indicate that the request is a recursive list request
// Supported options: WithRecursive
func (r *Repository) GrantsForToken(ctx context.Context, tokenId string, res []resource.Type, reqScopeId string, opt ...Option) (tempGrantTuples, error) {
	const op = "iam.(Repository).GrantsForToken"

	// validations
	if res == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing resource type")
	}
	if slices.Contains(res, resource.Unknown) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type cannot be unknown")
	}
	if slices.Contains(res, resource.All) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type cannot be all")
	}
	if tokenId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token id")
	}
	if reqScopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing request scope id")
	}

	switch {
	case strings.HasPrefix(reqScopeId, globals.GlobalPrefix):
	case strings.HasPrefix(reqScopeId, globals.OrgPrefix):
	case strings.HasPrefix(reqScopeId, globals.ProjectPrefix):
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "request scope must be global scope, an org scope, or a project scope")
	}

	// get options
	opts := getOpts(opt...)

	// find the correct query to use
	query, err := r.resolveAppTokenQuery(ctx, tokenId, res, reqScopeId, opts.withRecursive)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var args []any
	var resources []string

	resources = []string{resource.Unknown.String(), resource.All.String()}
	for _, res := range res {
		resources = append(resources, res.String())
	}

	args = append(args,
		sql.Named("app_token_ids", pq.Array([]string{tokenId})),
		sql.Named("request_scope_id", reqScopeId),
		sql.Named("resources", pq.Array(resources)),
	)

	var grants []grantsForTokenResult
	rows, err := r.reader.Query(ctx, query, args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()
	for rows.Next() {
		var g grantsForTokenResult
		if err := rows.Scan(
			&g.PermissionId,
			&g.Description,
			&g.CreateTime,
			&g.GrantThisScope,
			&g.GrantScope,
			&g.AppTokenId,
			pq.Array(&g.CanonicalGrants),
			pq.Array(&g.ActiveGrantScopes),
		); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	resp := make(tempGrantTuples, 0, len(grants))
	for _, grant := range grants {
		if grant.GrantThisScope {
			resp = append(resp, tempGrantTuple{
				AppTokenId:            grant.AppTokenId,
				AppTokenScopeId:       reqScopeId,
				AppTokenParentScopeId: "", // Not needed when GrantThisScope is true
				GrantScopeId:          grant.GrantScope,
				Grant:                 strings.Join(grant.CanonicalGrants, ","),
			})
		} else {
			resp = append(resp, tempGrantTuple{
				AppTokenId:            grant.AppTokenId,
				AppTokenScopeId:       reqScopeId,
				AppTokenParentScopeId: "", // How to determine parent scope id here?
				GrantScopeId:          grant.GrantScope,
				Grant:                 strings.Join(grant.CanonicalGrants, ","),
			})
		}
	}

	return resp, nil
}

// resolveAppTokenQuery determines the correct SQL query to use based on the token scope, request scope, resource types, and whether the request is recursive
func (r *Repository) resolveAppTokenQuery(ctx context.Context, tokenId string, res []resource.Type, reqScopeId string, isRecursive bool) (string, error) {
	const op = "iam.(Repository).resolveAppTokenQuery"

	// validations
	if res == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing resource type")
	}
	if slices.Contains(res, resource.Unknown) {
		return "", errors.New(ctx, errors.InvalidParameter, op, "resource type cannot be unknown")
	}
	if slices.Contains(res, resource.All) {
		return "", errors.New(ctx, errors.InvalidParameter, op, "resource type cannot be all")
	}
	if tokenId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing token id")
	}
	if reqScopeId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing request scope id")
	}

	switch {
	case strings.HasPrefix(reqScopeId, globals.GlobalPrefix):
	case strings.HasPrefix(reqScopeId, globals.OrgPrefix):
	case strings.HasPrefix(reqScopeId, globals.ProjectPrefix):
	default:
		return "", errors.New(ctx, errors.InvalidParameter, op, "request scope must be global scope, an org scope, or a project scope")
	}

	// Use the largest set of allowed scopes for the given resources
	var resourceAllowedIn []scope.Type
	for _, re := range res {
		a, err := scope.AllowedIn(ctx, re)
		if err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
		if len(a) > len(resourceAllowedIn) {
			resourceAllowedIn = a
		}
	}

	// Determine app token scope from tokenId prefix
	var isAppTokenGlobal, isAppTokenOrg, isAppTokenProject bool
	isAppTokenGlobal = strings.HasPrefix(reqScopeId, globals.GlobalPrefix)
	isAppTokenOrg = strings.HasPrefix(reqScopeId, globals.OrgPrefix)
	isAppTokenProject = strings.HasPrefix(reqScopeId, globals.ProjectPrefix)

	switch isRecursive {
	// Recursive queries - based on token scope and resource allowed scopes
	case true:
		switch {
		case isAppTokenGlobal:
			if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}) {
				return grantsForTokenGlobalOrgProjectResourcesRecursiveQuery, nil
			} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}) {
				return grantsForTokenGlobalOrgResourcesRecursiveQuery, nil
			}
		case isAppTokenOrg:
			if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}) {
				return grantsForTokenOrgGlobalOrgProjectResourcesRecursiveQuery, nil
			} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}) {
				return grantsForTokenOrgGlobalOrgResourcesRecursiveQuery, nil
			} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}) {
				return grantsForTokenOrgProjectResourcesRecursiveQuery, nil
			}
		case isAppTokenProject:
			return grantsForTokenProjectResourcesRecursiveQuery, nil
		}

		// Non-recursive queries - based on token scope, request scope, and resource allowed scopes
	case false:
		switch {
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global}):
			if reqScopeId != globals.GlobalPrefix {
				return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("request scope id must be global for %s resources", res))
			}
			if isAppTokenGlobal {
				return grantsForTokenGlobalOrgProjectResourcesQuery, nil
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}):
			switch {
			case strings.HasPrefix(reqScopeId, globals.GlobalPrefix):
				if isAppTokenGlobal {
					return grantsForTokenGlobalOrgResourcesQuery, nil
				} else if isAppTokenOrg {
					return grantsForTokenOrgGlobalOrgResourcesQuery, nil
				}
			case strings.HasPrefix(reqScopeId, globals.OrgPrefix):
				if isAppTokenGlobal {
					return grantsForTokenGlobalOrgResourcesQuery, nil
				} else if isAppTokenOrg {
					return grantsForTokenOrgGlobalOrgResourcesQuery, nil
				}
			default:
				return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("request scope id must be global or org for %s resources", res))
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}):
			switch {
			case strings.HasPrefix(reqScopeId, globals.GlobalPrefix):
				if isAppTokenGlobal {
					return grantsForTokenGlobalOrgProjectResourcesQuery, nil
				} else if isAppTokenOrg {
					return grantsForTokenOrgGlobalOrgProjectResourcesQuery, nil
				}
			case strings.HasPrefix(reqScopeId, globals.OrgPrefix):
				if isAppTokenGlobal {
					return grantsForTokenGlobalOrgResourcesQuery, nil
				} else if isAppTokenOrg {
					return grantsForTokenOrgGlobalOrgResourcesQuery, nil
				}
			case strings.HasPrefix(reqScopeId, globals.ProjectPrefix):
				if isAppTokenGlobal {
					return grantsForTokenGlobalOrgProjectResourcesQuery, nil
				} else if isAppTokenOrg {
					return grantsForTokenOrgProjectResourcesQuery, nil
				} else if isAppTokenProject {
					return grantsForTokenProjectResourcesQuery, nil
				}
			default:
				return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid scope id %s", reqScopeId))
			}
		case slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}):
			if !strings.HasPrefix(reqScopeId, globals.ProjectPrefix) {
				return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("request scope id must be project for %s resources", res))
			}
			if isAppTokenOrg {
				return grantsForTokenOrgProjectResourcesQuery, nil
			} else if isAppTokenProject {
				return grantsForTokenProjectResourcesQuery, nil
			}
		}
	}

	return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("no matching query found for token scope, request scope %s, and resource types %v", reqScopeId, res))
}
