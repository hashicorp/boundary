// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/types/resource"
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
	publicId     string
	updateTime   time.Time
	resourceType resource.Type
}

func (p *fakeItem) GetPublicId() string {
	return p.publicId
}

func (p *fakeItem) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(p.updateTime)
}

func (p *fakeItem) GetResourceType() resource.Type {
	return p.resourceType
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
		t.Parallel()
		t.Run("success", func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)
			updateTime := time.Now()
			opts, err := GetOpts(WithStartPageAfterItem(&fakeItem{"s_1", updateTime, resource.Session}))
			require.NoError(t, err)
			assert.Equal(opts.WithStartPageAfterItem.GetPublicId(), "s_1")
			assert.Equal(opts.WithStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
		})
		t.Run("nil item", func(t *testing.T) {
			_, err := GetOpts(WithStartPageAfterItem(nil))
			require.ErrorContains(t, err, "nil item")
		})
		t.Run("nil typed item", func(t *testing.T) {
			_, err := GetOpts(WithStartPageAfterItem((*fakeItem)(nil)))
			require.ErrorContains(t, err, "nil item")
		})
		t.Run("missing public id", func(t *testing.T) {
			_, err := GetOpts(WithStartPageAfterItem(&fakeItem{"", time.Now(), resource.Session}))
			require.ErrorContains(t, err, "missing public id")
		})
		t.Run("zero update time", func(t *testing.T) {
			_, err := GetOpts(WithStartPageAfterItem(&fakeItem{"some_id", time.Time{}, resource.Session}))
			require.ErrorContains(t, err, "missing update time")
		})
		t.Run("missing resource type", func(t *testing.T) {
			_, err := GetOpts(WithStartPageAfterItem(&fakeItem{"some_id", time.Now(), resource.Unknown}))
			require.ErrorContains(t, err, "missing resource type")
		})
	})
}
