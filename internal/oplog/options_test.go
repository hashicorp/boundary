// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithFieldMaskPaths", func(t *testing.T) {
		opts := GetOpts(WithFieldMaskPaths([]string{"test"}))
		testOpts := getDefaultOptions()
		testOpts[optionWithFieldMaskPaths] = []string{"test"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSetToNullPaths", func(t *testing.T) {
		opts := GetOpts(WithSetToNullPaths([]string{"test"}))
		testOpts := getDefaultOptions()
		testOpts[optionWithSetToNullPaths] = []string{"test"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAggregateNames", func(t *testing.T) {
		opts := GetOpts(WithAggregateNames(true))
		testOpts := getDefaultOptions()
		testOpts[optionWithAggregateNames] = true
		assert.Equal(opts, testOpts)
	})
}
