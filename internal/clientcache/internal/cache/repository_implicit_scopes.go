// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/errors"
)

func (r *Repository) ListImplicitScopes(ctx context.Context, authTokenId string, opt ...Option) (*SearchResult, error) {
	const op = "cache.(Repository).ListImplicitScopes"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchImplicitScopes(ctx, "true", nil, append(opt, withAuthTokenId(authTokenId))...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

// QueryImplicitScopes does nothing currently; it's not its own table, but a
// union of scope info from other types. So it just calls searchImplicitScopes
// as if it was a list. It is required to fulfill the interface, but will return
// an error if used from the API.
func (r *Repository) QueryImplicitScopes(ctx context.Context, authTokenId, query string, opt ...Option) (*SearchResult, error) {
	const op = "cache.(Repository).QueryImplicitScopes"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchImplicitScopes(ctx, "true", nil, append(opt, withAuthTokenId(authTokenId))...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchImplicitScopes(ctx context.Context, condition string, searchArgs []any, opt ...Option) (*SearchResult, error) {
	const op = "cache.(Repository).searchImplicitScopes"
	switch {
	case condition == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "condition is missing")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	switch {
	case opts.withAuthTokenId != "" && opts.withUserId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "both user id and auth token id were provided")
	case opts.withAuthTokenId == "" && opts.withUserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "neither user id nor auth token id were provided")

	// In these cases we append twice because we're doing a union of two tables
	case opts.withAuthTokenId != "":
		condition = "where fk_user_id in (select user_id from auth_token where id = ?)"
		searchArgs = append(searchArgs, opts.withAuthTokenId, opts.withAuthTokenId)
	case opts.withUserId != "":
		condition = "where fk_user_id = ?"
		searchArgs = append(searchArgs, opts.withUserId, opts.withUserId)
	}

	const unionQueryBase = `
		select distinct fk_user_id, scope_id from session
			%s
	union
		select distinct fk_user_id, scope_id from target
			%s
`
	unionQuery := fmt.Sprintf(unionQueryBase, condition, condition)

	rows, err := r.rw.Query(ctx, unionQuery, searchArgs)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	type ScopeIdsResult struct {
		FkUserId string `gorm:"primaryKey"`
		ScopeId  string `gorm:"default:null"`
	}

	var scopeIdsResults []ScopeIdsResult
	for rows.Next() {
		var res ScopeIdsResult
		if err := r.rw.ScanRows(ctx, rows, &res); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		scopeIdsResults = append(scopeIdsResults, res)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	dedupMap := make(map[string]struct{}, len(scopeIdsResults))
	for _, res := range scopeIdsResults {
		dedupMap[res.ScopeId] = struct{}{}
	}

	sr := &SearchResult{
		ImplicitScopes: make([]*scopes.Scope, 0, len(dedupMap)),
	}
	for k := range dedupMap {
		sr.ImplicitScopes = append(sr.ImplicitScopes, &scopes.Scope{Id: k})
	}

	return sr, nil
}
