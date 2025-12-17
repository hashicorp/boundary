// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithPrefix", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts(WithPrefix("test"))
		require.NoError(err)
		testOpts := getDefaultOptions()
		testOpts.withPrefix = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPrk", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts(WithPrk([]byte("test")))
		require.NoError(err)
		testOpts := getDefaultOptions()
		testOpts.withPrk = []byte("test")
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEd25519", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts(WithEd25519())
		require.NoError(err)
		testOpts := getDefaultOptions()
		testOpts.withEd25519 = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithBase64Encoding", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts(WithBase64Encoding())
		require.NoError(err)
		testOpts := getDefaultOptions()
		testOpts.withBase64Encoding = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithBase58Encoding", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts(WithBase58Encoding())
		require.NoError(err)
		testOpts := getDefaultOptions()
		testOpts.withBase58Encoding = true
		assert.Equal(opts, testOpts)
	})
}
