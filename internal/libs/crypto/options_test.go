package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithPrefix", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithPrefix("test"))
		testOpts := getDefaultOptions()
		testOpts.withPrefix = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPrk", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithPrk([]byte("test")))
		testOpts := getDefaultOptions()
		testOpts.withPrk = []byte("test")
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEd25519", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithEd25519())
		testOpts := getDefaultOptions()
		testOpts.withEd25519 = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithBase64Encoding", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithBase64Encoding())
		testOpts := getDefaultOptions()
		testOpts.withBase64Encoding = true
		assert.Equal(opts, testOpts)
	})
}
