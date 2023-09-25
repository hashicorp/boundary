// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
)

// TargetRetrievalFunc is a function that retrieves targets
// from the provided boundary addr using the provided token.
type TargetRetrievalFunc func(ctx context.Context, addr, token string) ([]*targets.Target, error)

func defaultTargetFunc(ctx context.Context, addr, token string) ([]*targets.Target, error) {
	const op = "cache.defaultTargetFunc"
	client, err := api.NewClient(&api.Config{
		Addr:  addr,
		Token: token,
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	tarClient := targets.NewClient(client)
	l, err := tarClient.List(ctx, "global", targets.WithRecursive(true))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return l.Items, nil
}

// SessionRetrievalFunc is a function that retrieves sessions
// from the provided boundary addr using the provided token.
type SessionRetrievalFunc func(ctx context.Context, addr, token string) ([]*sessions.Session, error)

func defaultSessionFunc(ctx context.Context, addr, token string) ([]*sessions.Session, error) {
	const op = "cache.defaultSessionFunc"
	client, err := api.NewClient(&api.Config{
		Addr:  addr,
		Token: token,
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	sClient := sessions.NewClient(client)
	l, err := sClient.List(ctx, "global", sessions.WithRecursive(true))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return l.Items, nil
}

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
	if err := r.cleanOrphanedAuthTokens(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	us, err := r.listUsers(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withTargetRetrievalFunc == nil {
		opts.withTargetRetrievalFunc = defaultTargetFunc
	}
	if opts.withSessionRetrievalFunc == nil {
		opts.withSessionRetrievalFunc = defaultSessionFunc
	}

	var retErr error
	for _, u := range us {
		tokens, err := r.cleanAndPickAuthTokens(ctx, u)
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op))
			continue
		}

		// Find and use a token for retrieving targets
		for at, t := range tokens {
			resp, err := opts.withTargetRetrievalFunc(ctx, u.Address, t)
			if err != nil {
				// TODO: If we get an error about the token no longer having
				// permissions, remove it.
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
				continue
			}

			event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d targets for user %v", len(resp), u))
			if err := r.refreshTargets(ctx, u, resp); err != nil {
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for user %v", u)))
			}
			break
		}

		// Find and use a token for retrieving sessions
		for at, t := range tokens {
			resp, err := opts.withSessionRetrievalFunc(ctx, u.Address, t)
			if err != nil {
				// TODO: If we get an error about the token no longer having
				// permissions, remove it.
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
				continue
			}

			event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d sessions for user %v", len(resp), u))
			if err := r.refreshSessions(ctx, u, resp); err != nil {
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for user %v", u)))
			}
			break
		}
	}
	return retErr
}
