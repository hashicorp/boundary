// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
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

// Refresh iterates over all tokens in the cache, attempts to read the
// resources for those tokens from boundary and updates the cache with
// the values retrieved there.  Refresh accepts the options
// WithTarget which overwrites the default function used to retrieve the
// targets from a boundary address.
func (r *Repository) Refresh(ctx context.Context, opt ...Option) error {
	const op = "cache.(Repository).Refresh"
	if err := r.removeStaleTokens(ctx); err != nil {
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
		tokens, err := r.listTokens(ctx, u)
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for user %v", u)))
			continue
		}

		// Find and use a token for retrieving targets
		for _, t := range tokens {
			at := r.tokenLookupFn(t.KeyringType, t.TokenName)
			if at == nil || at.Id != t.AuthTokenId {
				if err := r.deleteToken(ctx, t); err != nil {
					retErr = stderrors.Join(retErr, err)
				}
				continue
			}

			resp, err := opts.withTargetRetrievalFunc(ctx, u.Address, at.Token)
			if err != nil {
				// TODO: If we get an error about the token no longer having
				// permissions, remove it.
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %#v", u)))
				continue
			}

			event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d targets for user %v", len(resp), u))
			if err := r.refreshTargets(ctx, u, resp); err != nil {
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for user %v", u)))
			}
			break
		}

		// Find and use a token for retrieving sessions
		for _, t := range tokens {
			at := r.tokenLookupFn(t.KeyringType, t.TokenName)
			if at == nil || at.Id != t.AuthTokenId {
				if err := r.deleteToken(ctx, t); err != nil {
					retErr = stderrors.Join(retErr, err)
				}
				continue
			}

			resp, err := opts.withSessionRetrievalFunc(ctx, u.Address, at.Token)
			if err != nil {
				// TODO: If we get an error about the token no longer having
				// permissions, remove it.
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %#v", u)))
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
