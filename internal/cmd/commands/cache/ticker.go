// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cache

import (
	"context"
	stdErrors "errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
)

type refreshTicker struct {
	refreshInterval time.Duration
	store           *cache.Store
	cmd             commander
	tokenName       string
}

func newRefreshTicker(ctx context.Context, refreshIntervalSeconds int64, cmd commander, store *cache.Store, tokenName string) (*refreshTicker, error) {
	const op = "cache.newRefreshTicker"
	switch {
	case refreshIntervalSeconds == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refresh interval seconds is missing")
	case util.IsNil(cmd):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "cmd is missing")
	case util.IsNil(store):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "store is missing")
	case tokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	}

	// need to know if we can get a client
	_, err := cmd.Client()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	refreshInterval := defaultRefreshInterval
	if refreshIntervalSeconds != 0 {
		refreshInterval = time.Duration(refreshIntervalSeconds) * time.Second
	}
	return &refreshTicker{
		cmd:             cmd,
		refreshInterval: refreshInterval,
		store:           store,
		tokenName:       tokenName,
	}, nil
}

func (rt *refreshTicker) start(ctx context.Context) {
	const op = "cache.(refreshTicker).start"
	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			client, err := rt.cmd.Client()
			if err != nil {
				// emit event, reset, and continue
				errors.Wrap(ctx, err, op)
				timer.Reset(rt.refreshInterval)
				continue
			}
			if client.Token() == "" {
				// emit event, reset, and continue
				errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("token name %q is missing", rt.tokenName))
				timer.Reset(rt.refreshInterval)
				continue
			}
			if err := refreshCache(ctx, client, rt.tokenName, rt.store); err != nil {
				// event was already emitted, so reset and continue
				timer.Reset(rt.refreshInterval)
				continue
			}
			timer.Reset(rt.refreshInterval)
		}
	}
}

func refreshCache(ctx context.Context, client *api.Client, tokenName string, store *cache.Store) error {
	const op = "cache.(Repository).refreshCache"
	switch {
	case util.IsNil(client):
		return errors.New(ctx, errors.InvalidParameter, op, "api client is missing")
	case tokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case util.IsNil(store):
		return errors.New(ctx, errors.InvalidParameter, op, "store is missing")
	}
	r, err := cache.NewRepository(ctx, store)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	tarClient := targets.NewClient(client)
	l, err := tarClient.List(ctx, "global", targets.WithRecursive(true))
	if err != nil {
		if saveErr := r.SaveError(ctx, resource.Target.String(), err); saveErr != nil {
			return stdErrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
		return errors.Wrap(ctx, err, op)
	}

	event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d targets", len(l.Items)))
	if err := r.RefreshTargets(ctx, tokenName, l.Items); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
