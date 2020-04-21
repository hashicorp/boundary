package iam

import (
	"reflect"
	"testing"

	"gotest.tools/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithFriendlyName", func(t *testing.T) {
		opts := GetOpts(WithFriendlyName("test"))
		testOpts := getDefaultOptions()
		testOpts[optionWithFriendlyName] = "test"
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
}
