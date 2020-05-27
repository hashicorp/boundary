package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithParentKeyId", func(t *testing.T) {
		opts := getOpts(WithParentKeyId("test"))
		testOpts := getDefaultOptions()
		testOpts.withParentKeyId = "test"
		assert.Equal(opts, testOpts)
	})
}
