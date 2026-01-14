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
	t.Run("WithSort-default-sortby-ignored", func(t *testing.T) {
		opts, err := getOpts(WithSort(SortByDefault, Ascending, []SortBy{SortByName}))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithSort-empty-sortby-ignored", func(t *testing.T) {
		opts, err := getOpts(WithSort("", Ascending, []SortBy{SortByName}))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithSort-valid-name-ascending", func(t *testing.T) {
		opts, err := getOpts(WithSort(SortByName, Ascending, []SortBy{SortByName, SortByCreatedAt}))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withSortBy = SortByName
		testOpts.withSortDirection = Ascending
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithSort-valid-created_at-descending", func(t *testing.T) {
		opts, err := getOpts(WithSort(SortByCreatedAt, Descending, []SortBy{SortByCreatedAt}))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withSortBy = SortByCreatedAt
		testOpts.withSortDirection = Descending
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithSort-column-not-in-sortable-list", func(t *testing.T) {
		_, err := getOpts(WithSort(SortByName, Ascending, []SortBy{SortByCreatedAt}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errInvalidSortColumn.Error())
	})
	t.Run("WithSort-empty-sortable-columns", func(t *testing.T) {
		_, err := getOpts(WithSort(SortByName, Ascending, []SortBy{}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errInvalidSortColumn.Error())
	})
	t.Run("WithSort-nil-sortable-columns", func(t *testing.T) {
		_, err := getOpts(WithSort(SortByName, Ascending, nil))
		require.Error(t, err)
		assert.ErrorContains(t, err, errInvalidSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-semicolon", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name; DROP TABLE"), Ascending, []SortBy{SortBy("name; DROP TABLE")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-quote", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name'--"), Ascending, []SortBy{SortBy("name'--")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-double-quote", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name\"--"), Ascending, []SortBy{SortBy("name\"--")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-backslash", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name\\x00"), Ascending, []SortBy{SortBy("name\\x00")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-comma", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name,other"), Ascending, []SortBy{SortBy("name,other")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-parenthesis", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name("), Ascending, []SortBy{SortBy("name(")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-space", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name "), Ascending, []SortBy{SortBy("name ")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-tab", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name\t"), Ascending, []SortBy{SortBy("name\t")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-newline", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name\n"), Ascending, []SortBy{SortBy("name\n")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-unsafe-chars-dash", func(t *testing.T) {
		_, err := getOpts(WithSort(SortBy("name-col"), Ascending, []SortBy{SortBy("name-col")}))
		require.Error(t, err)
		assert.ErrorContains(t, err, errUnsafeSortColumn.Error())
	})
	t.Run("WithSort-default-direction", func(t *testing.T) {
		opts, err := getOpts(WithSort(SortByName, SortDirectionDefault, []SortBy{SortByName}))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withSortBy = SortByName
		testOpts.withSortDirection = SortDirectionDefault
		assert.Equal(t, opts, testOpts)
	})
}
