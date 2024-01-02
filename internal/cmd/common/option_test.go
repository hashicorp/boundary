// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("nil-options", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(nil, nil)
		require.NoError(err)
		testOpts := getDefaultOptions()
		assert.Equal(opts, testOpts)
	})

	t.Run("WithSkipScopeIdFlag", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts(WithSkipScopeIdFlag(true))
		require.NoError(err)
		testOpts := getDefaultOptions()
		testOpts.WithSkipScopeIdFlag = true
		assert.Equal(opts, testOpts)
	})
}
