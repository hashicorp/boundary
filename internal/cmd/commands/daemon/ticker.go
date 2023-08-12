// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	stdErrors "errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
)

type refreshTicker struct {
	refreshInterval time.Duration
	repo            *cache.Repository
	tokenFn         func(keyring string, tokenName string) *authtokens.AuthToken
}

// tokenLookupFn takes a token name and returns the token
type tokenLookupFn func(keyring string, tokenName string) *authtokens.AuthToken

func newRefreshTicker(ctx context.Context, refreshIntervalSeconds int64, store *cache.Store, tokenFn tokenLookupFn) (*refreshTicker, error) {
	const op = "daemon.newRefreshTicker"
	switch {
	case refreshIntervalSeconds == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refresh interval seconds is missing")
	case util.IsNil(store):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "repository is missing")
	}

	repo, err := cache.NewRepository(ctx, store)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	refreshInterval := defaultRefreshInterval
	if refreshIntervalSeconds != 0 {
		refreshInterval = time.Duration(refreshIntervalSeconds) * time.Second
	}
	return &refreshTicker{
		refreshInterval: refreshInterval,
		repo:            repo,
		tokenFn:         tokenFn,
	}, nil
}

func (rt *refreshTicker) start(ctx context.Context) {
	const op = "daemon.(refreshTicker).start"
	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := rt.repo.RemoveStalePersonas(ctx); err != nil {
				event.WriteError(ctx, op, err)
				timer.Reset(rt.refreshInterval)
				continue
			}
			personas, err := rt.repo.ListPersonas(ctx)
			if err != nil {
				event.WriteError(ctx, op, err)
				timer.Reset(rt.refreshInterval)
				continue
			}

			for _, p := range personas {
				at := p.Token(rt.tokenFn)
				if at == nil {
					if err := rt.repo.DeletePersona(ctx, p); err != nil {
						event.WriteError(ctx, op, err)
						continue
					}
				}

				client, err := api.NewClient(&api.Config{
					Addr:  p.BoundaryAddr,
					Token: at.Token,
				})
				if err != nil {
					event.WriteError(ctx, op, err)
					continue
				}
				if err := refreshCache(ctx, client, p, rt.repo); err != nil {
					continue
				}
			}
			timer.Reset(rt.refreshInterval)
		}
	}
}

func refreshCache(ctx context.Context, client *api.Client, p *cache.Persona, r *cache.Repository) error {
	const op = "daemon.(Repository).refreshCache"
	switch {
	case util.IsNil(client):
		return errors.New(ctx, errors.InvalidParameter, op, "client is missing")
	case util.IsNil(p):
		return errors.New(ctx, errors.InvalidParameter, op, "persona is missing")
	case p.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.BoundaryAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case util.IsNil(r):
		return errors.New(ctx, errors.InvalidParameter, op, "repository is missing")
	}

	tarClient := targets.NewClient(client)
	l, err := tarClient.List(ctx, "global", targets.WithRecursive(true))
	if err != nil {
		if saveErr := r.SaveError(ctx, resource.Target.String(), err); saveErr != nil {
			return stdErrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
		return errors.Wrap(ctx, err, op)
	}

	event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d targets for persona %v", len(l.Items), p))
	if err := r.RefreshTargets(ctx, p, l.Items); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
