package iam

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithFriendlyName", func(t *testing.T) {
		opts := GetOpts(WithFriendlyName("test"))
		testOpts := getDefaultOptions()
		testOpts[optionWithFriendlyName] = "test"
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithScope", func(t *testing.T) {
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)

		opts := GetOpts(WithScope(s))
		testOpts := getDefaultOptions()
		testOpts[optionWithScope] = s
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("optionWithDescription", func(t *testing.T) {
		opts := GetOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts[optionWithDescription] = "test desc"
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
}
