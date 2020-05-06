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
	t.Run("WithName", func(t *testing.T) {
		opts := GetOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithScope", func(t *testing.T) {
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)

		opts := GetOpts(WithScope(s))
		testOpts := getDefaultOptions()
		testOpts.withScope = s
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("optionWithDescription", func(t *testing.T) {
		opts := GetOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
}
