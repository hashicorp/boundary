// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/hashicorp/go-hclog"
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
	t.Run("WithUrl", func(t *testing.T) {
		opts, err := getOpts(WithUrl(ctx, "http://[::1]:9200"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withUrl = "http://[::1]:9200"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLogger", func(t *testing.T) {
		testLogger := hclog.NewNullLogger()
		opts, err := getOpts(WithLogger(ctx, testLogger))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withLogger = testLogger
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
	t.Run("withRecheckSupportInterval", func(t *testing.T) {
		opts, err := getOpts(withRecheckSupportInterval(ctx, time.Second))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withRecheckSupportInterval = time.Second
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withRecheckSupportInterval_negative", func(t *testing.T) {
		opts, err := getOpts(withRecheckSupportInterval(ctx, -time.Second))
		require.ErrorContains(t, err, "must be positive")
		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("testWithIntervalRandomizationFactor", func(t *testing.T) {
		opts, err := getOpts(testWithIntervalRandomizationFactor(ctx, 0.2))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.testWithIntervalRandomizationFactor = 0.2
		testOpts.testWithIntervalRandomizationFactorSet = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("testWithIntervalRandomizationFactor zero", func(t *testing.T) {
		opts, err := getOpts(testWithIntervalRandomizationFactor(ctx, 0))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.testWithIntervalRandomizationFactor = 0
		testOpts.testWithIntervalRandomizationFactorSet = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("testWithIntervalRandomizationFactor negative", func(t *testing.T) {
		opts, err := getOpts(testWithIntervalRandomizationFactor(ctx, -0.2))
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
	t.Run("WithHomeDir", func(t *testing.T) {
		opts, err := getOpts(WithHomeDir(ctx, "/tmp"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withHomeDir = "/tmp"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithForceResetSchema", func(t *testing.T) {
		opts, err := getOpts(WithForceResetSchema(ctx, true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.False(t, testOpts.withForceResetSchema)
		testOpts.withForceResetSchema = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithReadyToServeNotificationCh", func(t *testing.T) {
		ch := make(chan struct{})
		opts, err := getOpts(WithReadyToServeNotificationCh(ctx, ch))
		require.NoError(t, err)
		assert.NotNil(t, opts.WithReadyToServeNotificationCh)
		testOpts := getDefaultOptions()
		assert.Nil(t, testOpts.WithReadyToServeNotificationCh)
		testOpts.WithReadyToServeNotificationCh = ch
	})
}
