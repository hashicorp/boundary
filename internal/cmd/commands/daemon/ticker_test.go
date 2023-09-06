// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTickerRefresh(t *testing.T) {
	ctx := context.Background()

	called := make(chan struct{})
	testFunc := func(context.Context, ...cache.Option) error {
		called <- struct{}{}
		return nil
	}

	rt, err := newRefreshTicker(ctx, 60, testFunc)
	require.NoError(t, err)

	tickerCtx, tickerCancel := context.WithCancel(ctx)
	go rt.start(tickerCtx)
	t.Cleanup(func() {
		tickerCancel()
	})

	// let the normal start ticker refresh things,
	<-called

	testCtx, testCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer testCancel()
	rt.refresh()
	select {
	case <-called:
	case <-testCtx.Done():
		assert.Fail(t, "timed out waiting for the refresh ")
	}

	// wait and make sure we don't get yet another call
	select {
	case <-called:
		assert.Fail(t, "received an unexpected refresh call")
	case <-testCtx.Done():
	}
}
