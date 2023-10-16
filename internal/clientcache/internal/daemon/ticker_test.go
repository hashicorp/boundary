// Copyright (c) HashiCorp, Inc.
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

	rt, err := newRefreshTicker(ctx, 60, refresher)
	require.NoError(t, err)

	tickerCtx, tickerCancel := context.WithCancel(ctx)
	go rt.start(tickerCtx)
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

type fakeRefresher struct {
	called chan struct{}
}

func (r *fakeRefresher) Refresh(context.Context, ...cache.Option) error {
	r.called <- struct{}{}
	return nil
}
