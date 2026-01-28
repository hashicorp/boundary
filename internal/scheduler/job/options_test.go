// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithNextRunIn", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithNextRunIn(time.Hour))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withNextRunIn = time.Hour
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithLimit(100))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withLimit = 100
		assert.Equal(opts, testOpts)
	})
	t.Run("WithName", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithName("name"))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withName = "name"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithControllerId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithControllerId("controller_id"))
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withControllerId = "controller_id"
		assert.Equal(opts, testOpts)
	})
}
