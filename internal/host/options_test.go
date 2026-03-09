// Copyright IBM Corp. 2020, 2025
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
		t.Parallel()
		opts, err := GetOpts(WithLimit(1))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithLimit = 1
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOrderByCreateTime-desc", func(t *testing.T) {
		t.Parallel()
		opts, err := GetOpts(WithOrderByCreateTime(false))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithOrderByCreateTime = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOrderByCreateTime-asc", func(t *testing.T) {
		t.Parallel()
		opts, err := GetOpts(WithOrderByCreateTime(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithOrderByCreateTime = true
		testOpts.Ascending = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		t.Parallel()
		t.Run("nil item", func(t *testing.T) {
			t.Parallel()
			_, err := GetOpts(WithStartPageAfterItem(nil))
			require.Error(t, err)
		})
		assert := assert.New(t)
		updateTime := time.Now()
		opts, err := GetOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", updateTime}))
		require.NoError(t, err)
		assert.Equal(opts.WithStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.WithStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
	})
	t.Run("WithReaderWriter", func(t *testing.T) {
		t.Parallel()
		t.Run("nil writer", func(t *testing.T) {
			t.Parallel()
			_, err := GetOpts(WithReaderWriter(&db.Db{}, nil))
			require.Error(t, err)
		})
		t.Run("nil reader", func(t *testing.T) {
			t.Parallel()
			_, err := GetOpts(WithReaderWriter(nil, &db.Db{}))
			require.Error(t, err)
		})
		reader := &db.Db{}
		writer := &db.Db{}
		opts, err := GetOpts(WithReaderWriter(reader, writer))
		require.NoError(t, err)
		assert.Equal(t, reader, opts.WithReader)
		assert.Equal(t, writer, opts.WithWriter)
	})
}
