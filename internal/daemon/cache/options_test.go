// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"testing"

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
			withDbType: dbw.Sqlite,
		}
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUrl", func(t *testing.T) {
		url := "something"
		opts, err := getOpts(WithUrl(url))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withUrl = url
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDebug", func(t *testing.T) {
		opts, err := getOpts(WithDebug(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withDebug = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUpdateLastAccessedTime", func(t *testing.T) {
		opts, err := getOpts(WithUpdateLastAccessedTime(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withUpdateLastAccessedTime = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithBoundaryAddress", func(t *testing.T) {
		url := "something"
		opts, err := getOpts(WithBoundaryAddress(url))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withBoundaryAddress = url
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithAuthTokenId", func(t *testing.T) {
		id := "something"
		opts, err := getOpts(WithAuthTokenId(id))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withAuthTokenId = id
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithTargetRetrievalFunc", func(t *testing.T) {
		var f TargetRetrievalFunc = func(ctx context.Context, keyringstring, tokenName string) ([]*targets.Target, error) { return nil, nil }
		opts, err := getOpts(WithTargetRetrievalFunc(f))
		require.NoError(t, err)

		assert.NotNil(t, opts.withTargetRetrievalFunc)
		opts.withTargetRetrievalFunc = nil

		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
}
