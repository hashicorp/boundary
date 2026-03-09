// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"testing"

	"github.com/hashicorp/boundary/internal/perms"
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
	t.Run("WithUserIsAnonymous", func(t *testing.T) {
		assert := assert.New(t)

		opts := GetOpts()
		assert.False(opts.WithUserIsAnonymous)

		opts = GetOpts(WithUserIsAnonymous(true))
		assert.True(opts.WithUserIsAnonymous)
	})
	t.Run("WithOutputFields", func(t *testing.T) {
		assert := assert.New(t)

		opts := GetOpts()
		assert.Nil(opts.WithOutputFields)

		var out perms.OutputFields

		opts = GetOpts(WithOutputFields(&out))
		assert.NotNil(opts.WithOutputFields)
	})
	t.Run("WithManagedGroupIds", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		opts := GetOpts()
		assert.Nil(opts.WithManagedGroupIds)

		out := []string{"foobar"}

		opts = GetOpts(WithManagedGroupIds(out))
		require.Equal(out, opts.WithManagedGroupIds)
	})
	t.Run("WithMemberIds", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		opts := GetOpts()
		assert.Nil(opts.WithMemberIds)

		out := []string{"foobar"}

		opts = GetOpts(WithMemberIds(out))
		require.Equal(out, opts.WithMemberIds)
	})
	t.Run("WithHostSetIds", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		opts := GetOpts()
		assert.Nil(opts.WithHostSetIds)

		out := []string{"foobar"}

		opts = GetOpts(WithHostSetIds(out))
		require.Equal(out, opts.WithHostSetIds)
	})
}
