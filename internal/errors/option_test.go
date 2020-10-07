package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_getOpts provides unit tests for GetOpts and all the options
func Test_getOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithErrCode", func(t *testing.T) {
		assert := assert.New(t)
		// test default
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withErrCode = nil
		assert.Equal(opts, testOpts)

		// try setting it
		opts = GetOpts(WithErrCode(ErrCodeNotNull))
		c := ErrCodeNotNull
		testOpts.withErrCode = &c
		assert.Equal(opts, testOpts)
	})
	t.Run("WithErrorMsg", func(t *testing.T) {
		assert := assert.New(t)
		// test default
		opts := GetOpts()
		testOpts := getDefaultOptions()
		testOpts.withErrMsg = ""
		assert.Equal(opts, testOpts)

		// try setting it
		opts = GetOpts(WithErrorMsg("test msg"))
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

}
