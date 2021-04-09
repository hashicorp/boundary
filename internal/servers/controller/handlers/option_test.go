package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithDiscardUnknownFields", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withDiscardUnknownFields = false
		assert.Equal(opts, testOpts)

		opts = getOpts(WithDiscardUnknownFields(true))
		testOpts = getDefaultOptions()
		testOpts.withDiscardUnknownFields = true
		assert.Equal(opts, testOpts)

		opts = getOpts(WithDiscardUnknownFields(false))
		testOpts = getDefaultOptions()
		testOpts.withDiscardUnknownFields = false
		assert.Equal(opts, testOpts)
	})
}
