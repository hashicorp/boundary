package iam

import (
	"reflect"
	"testing"

	"gotest.tools/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithOwnerId", func(t *testing.T) {
		opts := GetOpts(WithOwnerId(1))
		testOpts := getDefaultOptions()
		testOpts[optionWithOwnerId] = uint32(1)
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithFriendlyName", func(t *testing.T) {
		opts := GetOpts(WithFriendlyName("test"))
		testOpts := getDefaultOptions()
		testOpts[optionWithFriendlyName] = "test"
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
	t.Run("AsRootUser", func(t *testing.T) {
		opts := GetOpts(AsRootUser(true))
		testOpts := getDefaultOptions()
		testOpts[optionAsRootUser] = true
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
}
