// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts()
		testOpts := options{
			withSupportsMultiplex: false,
			withKeys:              nil,
		}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSupportsMultiplex", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithSupportsMultiplex(true))
		testOpts := getDefaultOptions()
		testOpts.withSupportsMultiplex = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeys", func(t *testing.T) {
		ctx := context.Background()
		assert := assert.New(t)
		require := require.New(t)

		keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "foo")
		require.NoError(err)

		opts := getOpts(WithKeys(keys))
		testOpts := getDefaultOptions()
		testOpts.withKeys = keys
		assert.Equal(opts, testOpts)
	})
}
