package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("withScope", func(t *testing.T) {
		assert := assert.New(t)
		s, err := NewOrg()
		assert.NoError(err)
		assert.NotNil(s.Scope)

		opts := getOpts(withScope(s))
		testOpts := getDefaultOptions()
		testOpts.withScope = s
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withLimit = 0
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(-1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = -1
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = 1
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAutoVivify", func(t *testing.T) {
		assert := assert.New(t)
		// test default of false
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withAutoVivify = false
		assert.Equal(opts, testOpts)

		opts = getOpts(WithAutoVivify(true))
		testOpts = getDefaultOptions()
		testOpts.withAutoVivify = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithGrantScopeId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithGrantScopeId("o_1234"))
		testOpts := getDefaultOptions()
		testOpts.withGrantScopeId = "o_1234"
		assert.Equal(opts, testOpts)
	})
}
