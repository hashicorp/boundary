// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
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
}
