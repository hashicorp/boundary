// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeWriter struct {
	db.Writer
}

type fakeReader struct {
	db.Reader
}

type fakeItem struct {
	pagination.Item
	publicId   string
	updateTime time.Time
}

func (p *fakeItem) GetPublicId() string {
	return p.publicId
}

func (p *fakeItem) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(p.updateTime)
}

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithLimit", func(t *testing.T) {
		ctx := context.Background()
		opts, err := GetOpts()
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithLimit = -1
		assert.Equal(t, opts, testOpts)

		opts, err = GetOpts(WithLimit(ctx, -1))
		require.NoError(t, err)
		testOpts = getDefaultOptions()
		testOpts.WithLimit = -1
		assert.Equal(t, opts, testOpts)

		opts, err = GetOpts(WithLimit(ctx, 1))
		require.NoError(t, err)
		testOpts = getDefaultOptions()
		testOpts.WithLimit = 1
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithReaderWriter", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		t.Run("success", func(t *testing.T) {
			t.Parallel()
			opts := getDefaultOptions()
			assert.Empty(t, opts.WithReader)
			assert.Empty(t, opts.WithWriter)
			r, w := &fakeReader{}, &fakeWriter{}
			opts, err := GetOpts(WithReaderWriter(ctx, r, w))
			require.NoError(t, err)
			assert.Equal(t, r, opts.WithReader)
			assert.Equal(t, w, opts.WithWriter)
		})
		t.Run("nil reader", func(t *testing.T) {
			t.Parallel()
			w := &fakeWriter{}
			_, err := GetOpts(WithReaderWriter(ctx, nil, w))
			require.Error(t, err)
		})
		t.Run("nil interface reader", func(t *testing.T) {
			t.Parallel()
			w := &fakeWriter{}
			_, err := GetOpts(WithReaderWriter(ctx, (*fakeReader)(nil), w))
			require.Error(t, err)
		})
		t.Run("nil writer", func(t *testing.T) {
			t.Parallel()
			r := &fakeReader{}
			_, err := GetOpts(WithReaderWriter(ctx, r, nil))
			require.Error(t, err)
		})
		t.Run("nil interface writer", func(t *testing.T) {
			t.Parallel()
			r := &fakeReader{}
			_, err := GetOpts(WithReaderWriter(ctx, r, (*fakeWriter)(nil)))
			require.Error(t, err)
		})
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		updateTime := time.Now()
		opts, err := GetOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", updateTime}))
		require.NoError(t, err)
		assert.Equal(t, opts.WithStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(t, opts.WithStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
	})
	t.Run("WithUnauthenticatedUser", func(t *testing.T) {
		ctx := context.Background()
		opts, err := GetOpts(WithUnauthenticatedUser(ctx, true))
		require.NoError(t, err)
		assert.True(t, opts.WithUnauthenticatedUser)
	})
}
