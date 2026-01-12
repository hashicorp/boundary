// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"database/sql"
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
	PermissionId          string
	Description           string
	GrantThisScope        bool
	GrantScope            string
	AppTokenId            string
	AppTokenParentScopeId string
	CanonicalGrants       []string
	ActiveGrantScopes     []string
}

// GrantsForToken retrieves all grants for the given app token id and resource types within the given request scope id.
// Use WithRecursive option to indicate that the request is a recursive list request
// Supported options: WithRecursive
func (r *Repository) GrantsForToken(ctx context.Context, tokenId string, res []resource.Type, reqScopeId string, opt ...Option) (tempGrantTuples, error) {
	const op = "apptoken.(Repository).GrantsForToken"

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

	opts := getOpts(opt...)

	// get AppToken to get scope
	appToken, err := r.getAppTokenById(ctx, tokenId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// find the correct query to use
	query, err := r.resolveAppTokenQuery(ctx, appToken.ScopeId, res, reqScopeId, opts.withRecursive)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var args []any
	var resources []string

	resources = []string{resource.Unknown.String(), resource.All.String()}
	for _, r := range res {
		resources = append(resources, r.String())
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
		var activeGrantScopes any
		var g grantsForTokenResult
		if err := rows.Scan(
			&g.PermissionId,
			&g.Description,
			&g.GrantThisScope,
			&g.GrantScope,
			&g.AppTokenId,
			&g.AppTokenParentScopeId,
			pq.Array(&g.CanonicalGrants),
			&activeGrantScopes,
		); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		// The active grant scopes can sometimes come back as NULL rather than an empty array
		// so we need to skip scanning in that case
		if activeGrantScopes != nil && activeGrantScopes != "{NULL}" {
			if err := pq.Array(&g.ActiveGrantScopes).Scan(activeGrantScopes); err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
		}

		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	resp := make(tempGrantTuples, 0, len(grants))
	for _, grant := range grants {
		resp = append(resp, tempGrantTuple{
			AppTokenId:            grant.AppTokenId,
			AppTokenScopeId:       appToken.ScopeId,
			AppTokenParentScopeId: grant.AppTokenParentScopeId,
			GrantScopeId:          grant.GrantScope,
			Grant:                 strings.Join(grant.CanonicalGrants, ","),
		})
	}

	return resp, nil
}

// resolveAppTokenQuery determines the correct SQL query to use based on the token scope, request scope, resource types, and whether the request is recursive
func (r *Repository) resolveAppTokenQuery(ctx context.Context, tokenScope string, res []resource.Type, reqScopeId string, isRecursive bool) (string, error) {
	const op = "apptoken.(Repository).resolveAppTokenQuery"

	// Find the allowed-in scopes for the resource types
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

	// Determine app token scope from token scope prefix
	isAppTokenGlobal := strings.HasPrefix(tokenScope, globals.GlobalPrefix)
	isAppTokenOrg := strings.HasPrefix(tokenScope, globals.OrgPrefix)
	isAppTokenProject := strings.HasPrefix(tokenScope, globals.ProjectPrefix)

	// Determine request scope from request scope prefix
	isRequestScopeGlobal := strings.HasPrefix(reqScopeId, globals.GlobalPrefix)
	isRequestScopeOrg := strings.HasPrefix(reqScopeId, globals.OrgPrefix)
	isRequestScopeProject := strings.HasPrefix(reqScopeId, globals.ProjectPrefix)

	var query string
	var err error
	if isRecursive {
		query, err = r.selectRecursiveQuery(ctx, isAppTokenGlobal, isAppTokenOrg, isAppTokenProject, resourceAllowedIn)
	} else {
		query, err = r.selectNonRecursiveQuery(ctx, isAppTokenGlobal, isAppTokenOrg, isAppTokenProject, isRequestScopeGlobal, isRequestScopeOrg, isRequestScopeProject)
	}
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("no matching query found for token scope, request scope"))
	}

	return query, nil
}

// selectRecursiveQuery selects the appropriate recursive query based on the app token scope and resource allowed-in scopes
func (r *Repository) selectRecursiveQuery(ctx context.Context, isGlobal, isOrg, isProject bool, resourceAllowedIn []scope.Type) (string, error) {
	const op = "apptoken.(Repository).selectRecursiveQuery"

	switch {
	case isGlobal:
		if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}) {
			return grantsForGlobalTokenGlobalOrgProjectResourcesRecursiveQuery, nil
		} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}) {
			return grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery, nil
		} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}) {
			return grantsForGlobalTokenProjectResourcesRecursiveQuery, nil
		}
	case isOrg:
		if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}) {
			return grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery, nil
		} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}) {
			return grantsForOrgTokenGlobalOrgResourcesRecursiveQuery, nil
		} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}) {
			return grantsForOrgTokenProjectResourcesRecursiveQuery, nil
		}
	case isProject:
		return grantsForProjectTokenRecursiveQuery, nil
	}
	return "", errors.New(ctx, errors.InvalidParameter, op, "no matching recursive query found")
}

// selectNonRecursiveQuery selects the appropriate non-recursive query based on the app token scope, request scope, and resource allowed-in scopes
func (r *Repository) selectNonRecursiveQuery(ctx context.Context, isGlobal, isOrg, isProject bool, isReqGlobal, isReqOrg, isReqProject bool) (string, error) {
	const op = "apptoken.(Repository).selectNonRecursiveQuery"

	switch {
	case isGlobal:
		if isReqGlobal {
			return grantsForGlobalTokenGlobalRequestScopeQuery, nil
		} else if isReqOrg {
			return grantsForGlobalTokenOrgRequestScopeQuery, nil
		} else if isReqProject {
			return grantsForGlobalTokenProjectRequestScopeQuery, nil
		}
	case isOrg:
		if isReqOrg {
			return grantsForOrgTokenOrgRequestScopeQuery, nil
		} else if isReqProject {
			return grantsForOrgTokenProjectRequestScopeQuery, nil
		}
	case isProject:
		if isReqProject {
			return grantsForProjectTokenQuery, nil
		}
	}
	return "", errors.New(ctx, errors.InvalidParameter, op, "no matching non-recursive query found")
}
