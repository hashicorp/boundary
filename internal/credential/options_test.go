// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/internal/util/template"
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
	createTime time.Time
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

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithTemplateData", func(t *testing.T) {
		t.Parallel()
		opts := getDefaultOptions()
		assert.Empty(t, opts.WithTemplateData)
		opts, err := GetOpts(WithTemplateData(template.Data{User: template.User{Id: util.Pointer("foo")}}))
		require.NoError(t, err)
		assert.Equal(t, "foo", *opts.WithTemplateData.User.Id)
	})
	t.Run("WithLimit", func(t *testing.T) {
		t.Parallel()
		t.Run("success", func(t *testing.T) {
			t.Parallel()
			opts := getDefaultOptions()
			assert.Empty(t, opts.WithLimit)
			opts, err := GetOpts(WithLimit(1))
			require.NoError(t, err)
			assert.Equal(t, 1, opts.WithLimit)
		})
		t.Run("negative limit", func(t *testing.T) {
			t.Parallel()
			opts := getDefaultOptions()
			assert.Empty(t, opts.WithLimit)
			_, err := GetOpts(WithLimit(-1))
			require.Error(t, err)
		})
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
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		assert := assert.New(t)
		updateTime := time.Now()
		createTime := time.Now()
		opts, err := GetOpts(WithStartPageAfterItem(&fakeItem{nil, "s_1", updateTime, createTime}))
		require.NoError(t, err)
		assert.Equal(opts.WithStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.WithStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
		assert.Equal(opts.WithStartPageAfterItem.GetCreateTime(), timestamp.New(createTime))
	})

	t.Run("WithRandomReader", func(t *testing.T) {
		assert := assert.New(t)
		reader := strings.NewReader("notrandom")
		opts, err := GetOpts(WithRandomReader(reader))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithRandomReader = reader
		assert.Equal(opts, testOpts)
	})
}
