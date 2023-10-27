// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"testing"

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
			withDbType: dbw.Sqlite,
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
	t.Run("WithTargetRetrievalFunc", func(t *testing.T) {
		var f TargetRetrievalFunc = func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error) {
			return nil, nil, "", nil
		}
		opts, err := getOpts(WithTargetRetrievalFunc(f))
		require.NoError(t, err)

		assert.NotNil(t, opts.withTargetRetrievalFunc)
		opts.withTargetRetrievalFunc = nil

		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithSessionRetrievalFunc", func(t *testing.T) {
		var f SessionRetrievalFunc = func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue) ([]*sessions.Session, []string, RefreshTokenValue, error) {
			return nil, nil, "", nil
		}
		opts, err := getOpts(WithSessionRetrievalFunc(f))
		require.NoError(t, err)

		assert.NotNil(t, opts.withSessionRetrievalFunc)
		opts.withSessionRetrievalFunc = nil

		testOpts := getDefaultOptions()
		assert.Equal(t, opts, testOpts)
	})
}
