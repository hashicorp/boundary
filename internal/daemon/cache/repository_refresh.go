// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stderrors "errors"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/errors"
)

// cleanAndPickAuthTokens removes from the cache all auth tokens which are
// evicted from the cache or no longer stored in a keyring and returns the
// remaining ones.
// The returned auth tokens have not been validated against boundary
func (r *Repository) cleanAndPickAuthTokens(ctx context.Context, u *user) (map[AuthToken]string, error) {
	const op = "cache.(Repository).cleanAndPickAuthTokens"
	ret := make(map[AuthToken]string)

	tokens, err := r.listTokens(ctx, u)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for _, t := range tokens {
		keyringTokens, err := r.listKeyringTokens(ctx, t)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("for user %v, auth token %q", u, t.Id))
		}
		for _, kt := range keyringTokens {
			at := r.tokenKeyringFn(kt.KeyringType, kt.TokenName)
			switch {
			case at == nil, at.Id != kt.AuthTokenId:
				if err := r.deleteKeyringToken(ctx, *kt); err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
			case at != nil:
				ret[*t] = at.Token
			}
		}
		if atv, ok := r.idToKeyringlessAuthToken.Load(t.Id); ok {
			if at, ok := atv.(*authtokens.AuthToken); ok {
				ret[*t] = at.Token
			}
		}
	}
	return ret, nil
}

// Refresh iterates over all tokens in the cache, attempts to read the
// resources for those tokens from boundary and updates the cache with
// the values retrieved there.  Refresh accepts the options
// WithTarget which overwrites the default function used to retrieve the
// targets from a boundary address.
func (r *Repository) Refresh(ctx context.Context, opt ...Option) error {
	const op = "cache.(Repository).Refresh"
	if err := r.cleanExpiredOrOrphanedAuthTokens(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	us, err := r.listUsers(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	var retErr error
	for _, u := range us {
		tokens, err := r.cleanAndPickAuthTokens(ctx, u)
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
			continue
		}

		if err := r.refreshTargets(ctx, u, tokens, opt...); err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
		}
		if err := r.refreshSessions(ctx, u, tokens, opt...); err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
		}

	}
	return retErr
}
