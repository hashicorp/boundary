// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeItem struct {
	pagination.Item
	publicId   string
	createTime time.Time
	updateTime time.Time
}

func (p *fakeItem) GetPublicId() string {
	return p.publicId
}

func (p *fakeItem) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(p.updateTime)
}

func (p *fakeItem) GetCreateTime() *timestamp.Timestamp {
	return timestamp.New(p.createTime)
}

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithLimit", func(t *testing.T) {
		ctx := context.Background()
		opts, err := GetOpts()
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithLimit = 0
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
		t.Run("success", func(t *testing.T) {
			t.Parallel()
			_, err := GetOpts()
			require.NoError(t, err)
		})
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		assert := assert.New(t)
		updateTime := time.Now()
		createTime := time.Now()
		opts, err := GetOpts(WithStartPageAfterItem(context.Background(), &fakeItem{nil, "s_1", createTime, updateTime}))
		require.NoError(t, err)
		assert.Equal(opts.WithStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.WithStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
		assert.Equal(opts.WithStartPageAfterItem.GetCreateTime(), timestamp.New(createTime))
	})
	t.Run("WithUnauthenticatedUser", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		opts, err := GetOpts(WithUnauthenticatedUser(ctx, true))
		require.NoError(t, err)
		assert.True(t, opts.WithUnauthenticatedUser)
	})
}
