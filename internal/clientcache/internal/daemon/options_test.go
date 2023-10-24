// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("default", func(t *testing.T) {
		opts, err := getOpts()
		require.NoError(t, err)
		testOpts := options{}
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDebug", func(t *testing.T) {
		opts, err := getOpts(WithDebug(ctx, true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withDebug = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withRefreshInterval", func(t *testing.T) {
		opts, err := getOpts(withRefreshInterval(ctx, time.Second))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withRefreshInterval = time.Second
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withRefreshInterval_negative", func(t *testing.T) {
		opts, err := getOpts(withRefreshInterval(ctx, -time.Second))
		require.ErrorContains(t, err, "must be positive")
		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withFullFetchInterval", func(t *testing.T) {
		opts, err := getOpts(withFullFetchInterval(ctx, time.Second))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withFullFetchInterval = time.Second
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withFullFetchInterval_negative", func(t *testing.T) {
		opts, err := getOpts(withFullFetchInterval(ctx, -time.Second))
		require.ErrorContains(t, err, "must be positive")
		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withIntervalRandomizationFactor", func(t *testing.T) {
		opts, err := getOpts(withIntervalRandomizationFactor(ctx, 0.2))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withIntervalRandomizationFactor = 0.2
		testOpts.withIntervalRandomizationFactorSet = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withIntervalRandomizationFactor zero", func(t *testing.T) {
		opts, err := getOpts(withIntervalRandomizationFactor(ctx, 0))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withIntervalRandomizationFactor = 0
		testOpts.withIntervalRandomizationFactorSet = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withIntervalRandomizationFactor negative", func(t *testing.T) {
		opts, err := getOpts(withIntervalRandomizationFactor(ctx, -0.2))
		require.ErrorContains(t, err, "must be non negative")
		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithBoundaryTokenReaderFunc", func(t *testing.T) {
		var f cache.BoundaryTokenReaderFn = func(ctx context.Context, addr, token string) (*authtokens.AuthToken, error) {
			return nil, nil
		}
		opts, err := getOpts(WithBoundaryTokenReaderFunc(ctx, f))
		require.NoError(t, err)

		assert.NotNil(t, opts.withBoundaryTokenReaderFunc)
		opts.withBoundaryTokenReaderFunc = nil

		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
}
