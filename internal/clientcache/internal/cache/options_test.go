// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		opts, err := getOpts()
		require.NoError(t, err)
		testOpts := options{
			withDbType:           dbw.Sqlite,
			withMaxResultSetSize: defaultLimitedResultSetSize,
		}
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUpdateLastAccessedTime", func(t *testing.T) {
		opts, err := getOpts(WithUpdateLastAccessedTime(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withUpdateLastAccessedTime = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withUserId", func(t *testing.T) {
		opts, err := getOpts(withUserId("u123"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withUserId = "u123"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withAuthTokenId", func(t *testing.T) {
		opts, err := getOpts(withAuthTokenId("at123"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withAuthTokenId = "at123"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithTargetRetrievalFunc", func(t *testing.T) {
		var f TargetRetrievalFunc = func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue, inPage *targets.TargetListResult, opt ...Option) (*targets.TargetListResult, RefreshTokenValue, error) {
			return nil, "", nil
		}
		opts, err := getOpts(WithTargetRetrievalFunc(f))
		require.NoError(t, err)

		assert.NotNil(t, opts.withTargetRetrievalFunc)
		opts.withTargetRetrievalFunc = nil

		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithSessionRetrievalFunc", func(t *testing.T) {
		var f SessionRetrievalFunc = func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue, inPage *sessions.SessionListResult, opt ...Option) (*sessions.SessionListResult, RefreshTokenValue, error) {
			return nil, "", nil
		}
		opts, err := getOpts(WithSessionRetrievalFunc(f))
		require.NoError(t, err)

		assert.NotNil(t, opts.withSessionRetrievalFunc)
		opts.withSessionRetrievalFunc = nil

		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithAliasRetrievalFunc", func(t *testing.T) {
		var f ResolvableAliasRetrievalFunc = func(ctx context.Context, addr, authTok, userId string, refreshTok RefreshTokenValue, inPage *aliases.AliasListResult, opt ...Option) (*aliases.AliasListResult, RefreshTokenValue, error) {
			return nil, "", nil
		}
		opts, err := getOpts(WithAliasRetrievalFunc(f))
		require.NoError(t, err)

		assert.NotNil(t, opts.withResolvableAliasRetrievalFunc)
		opts.withResolvableAliasRetrievalFunc = nil

		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withIgnoreSearchStaleness", func(t *testing.T) {
		opts, err := getOpts(WithIgnoreSearchStaleness(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withIgnoreSearchStaleness = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withMaxResultSetSize", func(t *testing.T) {
		opts, err := getOpts(WithMaxResultSetSize(defaultLimitedResultSetSize))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withMaxResultSetSize = defaultLimitedResultSetSize
		assert.Equal(t, opts, testOpts)
		opts, err = getOpts(WithMaxResultSetSize(0))
		require.Nil(t, err)
		assert.Equal(t, opts, testOpts)
		_, err = getOpts(WithMaxResultSetSize(-2))
		require.Error(t, err)
	})
	t.Run("withTestRefreshWaitChs", func(t *testing.T) {
		waitCh := &testRefreshWaitChs{
			firstSempahore:  make(chan struct{}),
			secondSemaphore: make(chan struct{}),
		}
		opts, err := getOpts(WithTestRefreshWaitChs(waitCh))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.Empty(t, testOpts.withTestRefreshWaitChs)
		testOpts.withTestRefreshWaitChs = waitCh
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUseNonPagedListing", func(t *testing.T) {
		opts, err := getOpts(WithUseNonPagedListing(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.False(t, testOpts.withUseNonPagedListing)
		testOpts.withUseNonPagedListing = true
		assert.Equal(t, opts, testOpts)
	})
}
