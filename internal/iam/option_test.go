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
	t.Run("WithScope", func(t *testing.T) {
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)

		opts := GetOpts(WithScope(s))
		testOpts := getDefaultOptions()
		testOpts[optionWithScope] = s
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
	t.Run("optionWithDescription", func(t *testing.T) {
		opts := GetOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts[optionWithDescription] = "test desc"
		assert.Check(t, reflect.DeepEqual(opts, testOpts))
	})
}
