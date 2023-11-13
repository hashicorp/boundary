// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"math/rand"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
)

const (
	DefaultRefreshInterval = 60 * time.Second

	DefaultFullFetchInterval = 60 * 5 * time.Second

	defaultRandomizationFactor float64 = 0.2
)

type refreshService interface {
	Refresh(context.Context, ...cache.Option) error
	FullFetch(context.Context, ...cache.Option) error
}

type refreshTicker struct {
	tickerCtx           context.Context
	refreshInterval     time.Duration
	fullFetchInterval   time.Duration
	randomizationFactor float64
	rand                *rand.Rand
	refreshChan         chan struct{}
	refresher           refreshService
}

// newRefreshTicker creates a new refresh ticker. Accepted options are
// withRefreshInterval, and withFullFetchInterval.
// testWithIntervalRandomizationFactor is provided for tests.
// The intervals can deviate +/- randomizationFactor * configured interval.
// For example, an interval of 10 seconds and a randomization factor of 0.2 will
// encounter intervals of 8 to 12 seconds since 10 * .2 is 2 seconds and 10 +/- 2
// is 8 to 12.
func newRefreshTicker(ctx context.Context, refresh refreshService, opt ...Option) (*refreshTicker, error) {
	const op = "daemon.newRefreshTicker"
	switch {
	case util.IsNil(refresh):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "refreshing function is missing")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	refreshInterval := DefaultRefreshInterval
	if opts.withRefreshInterval != 0 {
		refreshInterval = opts.withRefreshInterval
	}

	fullFetchInterval := DefaultFullFetchInterval
	if opts.withFullFetchInterval != 0 {
		fullFetchInterval = opts.withFullFetchInterval
	}

	randomizationFactor := defaultRandomizationFactor
	if opts.testWithIntervalRandomizationFactorSet {
		randomizationFactor = opts.testWithIntervalRandomizationFactor
	}

	return &refreshTicker{
		refreshInterval:     refreshInterval,
		fullFetchInterval:   fullFetchInterval,
		randomizationFactor: randomizationFactor,
		rand:                rand.New(rand.NewSource(time.Now().UnixNano())),
		refresher:           refresh,

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

func (rt *refreshTicker) startFullFetch(ctx context.Context) {
	const op = "daemon.(refreshTicker).startFullFetch"
	timer := time.NewTimer(0)
	for {
		// full fetch doesn't listen to the refreshChan since completely new
		// users are handled by refresh since we don't know if the new user
		// is for a boundary instance that supports refresh tokens.
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := rt.refresher.FullFetch(ctx); err != nil {
			event.WriteError(rt.tickerCtx, op, err)
		}
		timer.Reset(rt.nextIntervalWithRandomness(rt.fullFetchInterval))
	}
}

// startRefresh repeatedly calls Refresh on the this refreshTicker's refresher
// at some interval.  This interval can be overwritten by using the withDuration
// option when calling startRefresh
func (rt *refreshTicker) startRefresh(ctx context.Context) {
	const op = "daemon.(refreshTicker).startRefresh"
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
		timer.Reset(rt.nextIntervalWithRandomness(rt.refreshInterval))
	}
}

// nextIntervalWithRandomness applies the ticker's randomization factor to the
// provided duration and returns a newly calculated duration.  If the tickers
// randomization factor is 0 the returned duration is the same as the provided.
func (rt *refreshTicker) nextIntervalWithRandomness(d time.Duration) time.Duration {
	if rt.randomizationFactor == 0 {
		return d
	}

	randFactor := rt.rand.Float64()
	randFactor = randFactor * rt.randomizationFactor

	randDur := randFactor * float64(d)
	// Half a chance to be faster, not slower
	if rt.rand.Float32() > 0.5 {
		randDur = -1 * randDur
	}
	return d + time.Duration(randDur)
}
