// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

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
	permissionId          string
	description           string
	createTime            string
	grantThisScope        bool
	grantScope            string
	appTokenId            string
	appTokenParentScopeId string
	canonicalGrants       []string
	activeGrantScopes     []string
}

// GrantsForToken retrieves all grants for the given app token id and resource types within the given request scope id.
// Use WithRecursive option to indicate that the request is a recursive list request
// Supported options: WithRecursive
func (r *Repository) GrantsForToken(ctx context.Context, tokenId string, res []resource.Type, reqScopeId string, opt ...Option) (tempGrantTuples, error) {
	const op = "apptoken.(Repository).GrantsForToken"

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

	// get AppToken to get scope
	appToken, err := r.getAppTokenById(ctx, tokenId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if appToken == nil {
		return nil, errors.New(ctx, errors.NotFound, op, "app token not found")
	}

	// find the correct query to use
	query, err := r.resolveAppTokenQuery(ctx, appToken.ScopeId, res, reqScopeId, opts.withRecursive)
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
			&g.permissionId,
			&g.description,
			&g.createTime,
			&g.grantThisScope,
			&g.grantScope,
			&g.appTokenId,
			&g.appTokenParentScopeId,
			pq.Array(&g.canonicalGrants),
			pq.Array(&g.activeGrantScopes),
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
		if grant.grantThisScope {
			resp = append(resp, tempGrantTuple{
				AppTokenId:            grant.appTokenId,
				AppTokenScopeId:       appToken.ScopeId,
				AppTokenParentScopeId: "", // Not needed when GrantThisScope is true
				GrantScopeId:          grant.grantScope,
				Grant:                 strings.Join(grant.canonicalGrants, ","),
			})
		} else {
			resp = append(resp, tempGrantTuple{
				AppTokenId:            grant.appTokenId,
				AppTokenScopeId:       appToken.ScopeId,
				AppTokenParentScopeId: grant.appTokenParentScopeId,
				GrantScopeId:          grant.grantScope,
				Grant:                 strings.Join(grant.canonicalGrants, ","),
			})
		}
	}

	return resp, nil
}

// resolveAppTokenQuery determines the correct SQL query to use based on the token scope, request scope, resource types, and whether the request is recursive
func (r *Repository) resolveAppTokenQuery(ctx context.Context, tokenScope string, res []resource.Type, reqScopeId string, isRecursive bool) (string, error) {
	const op = "apptoken.(Repository).resolveAppTokenQuery"

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
	if tokenScope == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing token scope")
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

	// Determine app token scope from token scope prefix
	var isAppTokenGlobal, isAppTokenOrg, isAppTokenProject bool
	isAppTokenGlobal = strings.HasPrefix(tokenScope, globals.GlobalPrefix)
	isAppTokenOrg = strings.HasPrefix(tokenScope, globals.OrgPrefix)
	isAppTokenProject = strings.HasPrefix(tokenScope, globals.ProjectPrefix)

	// Determine request scope from request scope prefix
	var isRequestScopeGlobal, isRequestScopeOrg, isRequestScopeProject bool
	isRequestScopeGlobal = strings.HasPrefix(reqScopeId, globals.GlobalPrefix)
	isRequestScopeOrg = strings.HasPrefix(reqScopeId, globals.OrgPrefix)
	isRequestScopeProject = strings.HasPrefix(reqScopeId, globals.ProjectPrefix)

	switch isRecursive {
	// Recursive queries - based on token scope and resource allowed scopes
	case true:
		switch {
		case isAppTokenGlobal:
			if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}) {
				return grantsForGlobalTokenGlobalOrgProjectResourcesRecursiveQuery, nil
			} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}) {
				return grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery, nil
			} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}) {
				return grantsForGlobalTokenProjectResourcesRecursiveQuery, nil
			}
		case isAppTokenOrg:
			if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}) {
				return grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery, nil
			} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}) {
				return grantsForOrgTokenGlobalOrgResourcesRecursiveQuery, nil
			} else if slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}) {
				return grantsForOrgTokenProjectResourcesRecursiveQuery, nil
			}
		case isAppTokenProject:
			return grantsForProjectTokenResourcesRecursiveQuery, nil
		}

		// Non-recursive queries - based on token scope, request scope, and resource allowed scopes
	case false:
		switch {
		case isAppTokenGlobal:
			if isRequestScopeGlobal && slices.Contains(resourceAllowedIn, scope.Global) {
				return grantsForGlobalTokenGlobalResourcesQuery, nil
			} else if isRequestScopeOrg && slices.Contains(resourceAllowedIn, scope.Org) {
				return grantsForGlobalTokenOrgResourcesQuery, nil
			} else if isRequestScopeProject && slices.Contains(resourceAllowedIn, scope.Project) {
				return grantsForGlobalTokenProjectResourcesQuery, nil
			}
		case isAppTokenOrg:
			if isRequestScopeOrg && slices.Contains(resourceAllowedIn, scope.Org) {
				return grantsForOrgTokenOrgResourcesQuery, nil
			} else if isRequestScopeProject && slices.Contains(resourceAllowedIn, scope.Project) {
				return grantsForOrgTokenProjectResourcesQuery, nil
			}
		case isAppTokenProject:
			return grantsForProjectTokenResourcesQuery, nil
		}
	}

	return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("no matching query found for token scope, request scope %s, and resource types %v", reqScopeId, res))
}
