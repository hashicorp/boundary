// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
			withSha256Sum:         nil,
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
	t.Run("WithSha256Sum", func(t *testing.T) {
		// echo "test" | sha256sum
		sum := []byte(`f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2`)
		assert := assert.New(t)
		opts := getOpts(WithSha256Sum(sum))
		testOpts := getDefaultOptions()
		testOpts.withSha256Sum = sum
		assert.Equal(opts, testOpts)
	})
}
