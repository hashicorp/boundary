// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTickerRefresh(t *testing.T) {
	ctx := context.Background()

	refresher := &fakeRefresher{make(chan struct{})}

	rt, err := newRefreshTicker(ctx, refresher)
	require.NoError(t, err)

	tickerCtx, tickerCancel := context.WithCancel(ctx)
	go rt.startRefresh(tickerCtx)
	t.Cleanup(func() {
		tickerCancel()
	})

	// let the normal start ticker refresh things,
	<-refresher.called

	testCtx, testCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer testCancel()
	rt.refresh()
	select {
	case <-refresher.called:
	case <-testCtx.Done():
		assert.Fail(t, "timed out waiting for the refresh ")
	}

	// wait and make sure we don't get yet another call
	select {
	case <-refresher.called:
		assert.Fail(t, "received an unexpected refresh call")
	case <-testCtx.Done():
	}
}

func TestTickerRecheckCachingSupport(t *testing.T) {
	ctx := context.Background()

	refresher := &fakeRefresher{make(chan struct{})}

	rt, err := newRefreshTicker(ctx, refresher)
	require.NoError(t, err)

	tickerCtx, tickerCancel := context.WithCancel(ctx)
	go rt.startRecheckCachingSupport(tickerCtx)
	t.Cleanup(func() {
		tickerCancel()
	})

	// let the normal start ticker refresh things,
	<-refresher.called

	testCtx, testCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer testCancel()
	rt.refresh()
	select {
	case <-refresher.called:
		assert.Fail(t, "full fetch called as a result of refresh()")
	case <-testCtx.Done():
	}
}

func TestNextIntervalWithRandomness(t *testing.T) {
	ctx := context.Background()
	refresher := &fakeRefresher{make(chan struct{})}
	rt, err := newRefreshTicker(ctx, refresher, testWithIntervalRandomizationFactor(ctx, .2))
	require.NoError(t, err)

	interval := 10 * time.Second
	max, min := interval, interval
	for i := 0; i < 100; i++ {
		got := rt.nextIntervalWithRandomness(10 * time.Second)
		if got > max {
			max = got
		}
		if got < min {
			min = got
		}
	}
	assert.GreaterOrEqual(t, min, 8*time.Second)
	assert.LessOrEqual(t, max, 12*time.Second)
	assert.Less(t, min, interval)
	assert.Greater(t, max, interval)
}

type fakeRefresher struct {
	called chan struct{}
}

func (r *fakeRefresher) Refresh(context.Context, ...cache.Option) error {
	r.called <- struct{}{}
	return nil
}

func (r *fakeRefresher) RecheckCachingSupport(context.Context, ...cache.Option) error {
	r.called <- struct{}{}
	return nil
}
