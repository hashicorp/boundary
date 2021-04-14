package handlers

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithDiscardUnknownFields", func(t *testing.T) {
		assert := assert.New(t)

		opts := GetOpts()
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)

		opts = GetOpts(WithDiscardUnknownFields(true))
		testOpts = getDefaultOptions()
		testOpts.withDiscardUnknownFields = true
		assert.Equal(opts, testOpts)

		opts = GetOpts(WithDiscardUnknownFields(false))
		testOpts = getDefaultOptions()
		testOpts.withDiscardUnknownFields = false
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLogger", func(t *testing.T) {
		assert := assert.New(t)

		opts := GetOpts()
		assert.Nil(opts.WithLogger)

		opts = GetOpts(WithLogger(hclog.New(nil)))
		assert.NotNil(opts.WithLogger)
	})
}
