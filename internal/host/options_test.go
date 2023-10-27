// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host

import (
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

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithLimit", func(t *testing.T) {
		opts, err := GetOpts(WithLimit(1))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithLimit = 1
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOrderByCreateTime-desc", func(t *testing.T) {
		opts, err := GetOpts(WithOrderByCreateTime(false))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithOrderByCreateTime = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOrderByCreateTime-asc", func(t *testing.T) {
		opts, err := GetOpts(WithOrderByCreateTime(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithOrderByCreateTime = true
		testOpts.Ascending = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		assert := assert.New(t)
		updateTime := time.Now()
		opts, err := GetOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", updateTime}))
		require.NoError(t, err)
		assert.Equal(opts.WithStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.WithStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
	})
	t.Run("WithReaderWriter", func(t *testing.T) {
		t.Parallel()
		t.Run("success", func(t *testing.T) {
			t.Parallel()
			opts := getDefaultOptions()
			assert.Empty(t, opts.WithReader)
			assert.Empty(t, opts.WithWriter)
			r, w := &fakeReader{}, &fakeWriter{}
			opts, err := GetOpts(WithReaderWriter(r, w))
			require.NoError(t, err)
			assert.Equal(t, r, opts.WithReader)
			assert.Equal(t, w, opts.WithWriter)
		})
		t.Run("nil reader", func(t *testing.T) {
			t.Parallel()
			w := &fakeWriter{}
			_, err := GetOpts(WithReaderWriter(nil, w))
			require.Error(t, err)
		})
		t.Run("nil interface reader", func(t *testing.T) {
			t.Parallel()
			w := &fakeWriter{}
			_, err := GetOpts(WithReaderWriter((*fakeReader)(nil), w))
			require.Error(t, err)
		})
		t.Run("nil writer", func(t *testing.T) {
			t.Parallel()
			r := &fakeReader{}
			_, err := GetOpts(WithReaderWriter(r, nil))
			require.Error(t, err)
		})
		t.Run("nil interface writer", func(t *testing.T) {
			t.Parallel()
			r := &fakeReader{}
			_, err := GetOpts(WithReaderWriter(r, (*fakeWriter)(nil)))
			require.Error(t, err)
		})
	})
}
