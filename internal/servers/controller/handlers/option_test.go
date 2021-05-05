package handlers

import (
	"testing"

	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	t.Run("WithUserIsAnonymous", func(t *testing.T) {
		assert := assert.New(t)

		opts := GetOpts()
		assert.False(opts.WithUserIsAnonymous)

		opts = GetOpts(WithUserIsAnonymous(true))
		assert.True(opts.WithUserIsAnonymous)
	})
	t.Run("WithOutputFields", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		opts := GetOpts()
		assert.Nil(opts.WithOutputFields)

		var out perms.OutputFieldsMap

		opts = GetOpts(WithOutputFields(&out))
		require.NotNil(opts.WithOutputFields)
		assert.Nil(*opts.WithOutputFields)
	})
}
