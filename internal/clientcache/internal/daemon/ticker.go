// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
)

const (
	DefaultRefreshIntervalSeconds = 5 * 60
	defaultRefreshInterval        = DefaultRefreshIntervalSeconds * time.Second
)

type refreshService interface {
	Refresh(context.Context, ...cache.Option) error
}

type refreshTicker struct {
	tickerCtx       context.Context
	refreshInterval time.Duration
	refreshChan     chan struct{}
	refresher       refreshService
}

func newRefreshTicker(ctx context.Context, refreshIntervalSeconds int64, refresh refreshService) (*refreshTicker, error) {
	const op = "daemon.newRefreshTicker"
	switch {
	case refreshIntervalSeconds == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refresh interval seconds is missing")
	case util.IsNil(refresh):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refreshing function is missing")
	}

	refreshInterval := defaultRefreshInterval
	if refreshIntervalSeconds != 0 {
		refreshInterval = time.Duration(refreshIntervalSeconds) * time.Second
	}
	return &refreshTicker{
		refreshInterval: refreshInterval,
		refresher:       refresh,

		// We make this channel size 1 so if something happens midway through the refresh
		// we can immediately refresh again immediately to pick up something that might have been
		// missed the first time through.
		refreshChan: make(chan struct{}, 1),
	}, nil
}

// refresh starts the refresh logic if it is currently waiting. If refresh is
// currently happening then this queues a refresh for when the current refresh
// iteration is done, unless there is already a refresh queued in which case
// this is a noop.
func (rt *refreshTicker) refresh() {
	select {
	case rt.refreshChan <- struct{}{}:
	default:
	}
}

func (rt *refreshTicker) start(ctx context.Context) {
	const op = "daemon.(refreshTicker).start"
	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-rt.refreshChan:
		}
		if err := rt.refresher.Refresh(ctx); err != nil {
			event.WriteError(rt.tickerCtx, op, err)
		}
		timer.Reset(rt.refreshInterval)
	}
}
