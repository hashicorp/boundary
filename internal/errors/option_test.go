package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_getOpts provides unit tests for GetOpts and all the options
func Test_getOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithMsg", func(t *testing.T) {
		assert := assert.New(t)
		// test default
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withErrMsg = ""
		assert.Equal(opts, testOpts)

		// try setting it
		opts = GetOpts(WithMsg("test msg"))
		testOpts.withErrMsg = "test msg"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithWrap", func(t *testing.T) {
		assert := assert.New(t)
		// test default
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withErrWrapped = nil
		assert.Equal(opts, testOpts)

		// try setting it
		opts = GetOpts(WithWrap(ErrInvalidParameter))
		testOpts.withErrWrapped = ErrInvalidParameter
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOp", func(t *testing.T) {
		assert := assert.New(t)
		// test default
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withOp = nil
		assert.Equal(opts, testOpts)

		// try setting it
		opts = GetOpts(WithOp("alice.bob"))
		assert.Equal("alice.bob", string(*opts.withOp))
		// verify all other options are still equal
		opts.withOp = nil
		assert.Equal(opts, testOpts)
	})
}
