// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package host

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithLimit", func(t *testing.T) {
		opts, err := GetOpts(WithLimit(1))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithLimit = 1
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOrderByCreateTime-desc", func(t *testing.T) {
		opts, err := GetOpts(WithOrderByCreateTime(false))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithOrderByCreateTime = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOrderByCreateTime-asc", func(t *testing.T) {
		opts, err := GetOpts(WithOrderByCreateTime(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithOrderByCreateTime = true
		testOpts.Ascending = true
		assert.Equal(t, opts, testOpts)
	})
}
