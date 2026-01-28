// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package checksum

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	require := require.New(t)
	t.Run("WithPrefix", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.Empty(testOpts.withPrefix)

		opts := getDefaultOptions()
		opts.withPrefix = "test"
		testOpts, err = getOpts(WithPrefix("test"))
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
	t.Run("WithPrk", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.Empty(testOpts.withPrk)

		opts := getDefaultOptions()
		opts.withPrk = []byte("test")
		testOpts, err = getOpts(WithPrk([]byte("test")))
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
	t.Run("WithEd25519", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.False(testOpts.withEd25519)

		opts := getDefaultOptions()
		opts.withEd25519 = true
		testOpts, err = getOpts(WithEd25519())
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
	t.Run("WithBase64Encoding", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.False(testOpts.withBase64Encoding)

		opts := getDefaultOptions()
		opts.withBase64Encoding = true
		testOpts, err = getOpts(WithBase64Encoding())
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
	t.Run("WithBase58Encoding", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.False(testOpts.withBase58Encoding)

		opts := getDefaultOptions()
		opts.withBase58Encoding = true
		testOpts, err = getOpts(WithBase58Encoding())
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
	t.Run("WithMarshaledSigInfo", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.False(testOpts.withMarshaledSigInfo)

		opts := getDefaultOptions()
		opts.withMarshaledSigInfo = true
		testOpts, err = getOpts(WithMarshaledSigInfo())
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
	t.Run("WithSalt", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.Empty(testOpts.withSalt)

		opts := getDefaultOptions()
		opts.withSalt = []byte("test")
		testOpts, err = getOpts(WithSalt([]byte("test")))
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
	t.Run("WithInfo", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.Empty(testOpts.withInfo)

		opts := getDefaultOptions()
		opts.withInfo = []byte("test")
		testOpts, err = getOpts(WithInfo([]byte("test")))
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
	t.Run("WithHexEncoding", func(t *testing.T) {
		testOpts, err := getOpts()
		require.NoError(err)
		assert.False(testOpts.WithHexEncoding)

		opts := getDefaultOptions()
		opts.WithHexEncoding = true
		testOpts, err = getOpts(WithHexEncoding(true))
		require.NoError(err)
		assert.EqualValues(opts, *testOpts)
	})
}
