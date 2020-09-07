package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
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
	t.Run("WithScopeId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithScopeId("o_1234"))
		testOpts := getDefaultOptions()
		testOpts.withScopeId = "o_1234"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrder", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithOrder("create_time asc"))
		testOpts := getDefaultOptions()
		testOpts.withOrder = "create_time asc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithUserId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithUserId("u_1234"))
		testOpts := getDefaultOptions()
		testOpts.withUserId = "u_1234"
		assert.Equal(opts, testOpts)
	})
}
