// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
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

// Refresh iterates over all personas in the cache, attempts to read the
// resources for those personas from boundary and updates the cache with
// the values retrieved there.  Refresh accepts the options
// WithTarget which overwrites the default function used to retrieve the
// targets from a boundary address.
func (r *Repository) Refresh(ctx context.Context, opt ...Option) error {
	const op = "cache.(Repository).Refresh"
	if err := r.removeStalePersonas(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withTargetRetrievalFunc == nil {
		opts.withTargetRetrievalFunc = defaultTargetFunc
	}

	personas, err := r.listPersonas(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var retErr error
	for _, p := range personas {

		at := r.tokenLookupFn(p.KeyringType, p.TokenName)
		if at == nil {
			if err := r.deletePersona(ctx, p); err != nil {
				retErr = stderrors.Join(retErr, err)
			}
			continue
		}

		tars, err := opts.withTargetRetrievalFunc(ctx, p.BoundaryAddr, at.Token)
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for persona %#v", p)))
			continue
		}

		event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d targets for persona %v", len(tars), p))
		if err := r.refreshCachedTargets(ctx, p, tars); err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for persona %v", p)))
			continue
		}
	}
	return retErr
}
