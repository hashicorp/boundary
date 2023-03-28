// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_getOpts provides unit tests for GetOpts and all the options
func Test_getOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithCloseSyncMode", func(t *testing.T) {
		testOpts := getDefaultOptions()
		opts := getOpts(WithCloseSyncMode(Asynchronous))
		assert.Equal(testOpts, opts)

		testOpts = getDefaultOptions()
		opts = getOpts(WithCloseSyncMode(Synchronous))
		testOpts.withCloseSyncMode = Synchronous
		assert.Equal(opts, testOpts)

		testOpts = getDefaultOptions()
		opts = getOpts(WithCloseSyncMode(NoSync))
		testOpts.withCloseSyncMode = NoSync
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFileAccessMode", func(t *testing.T) {
		testOpts := getDefaultOptions()
		opts := getOpts(WithFileAccessMode(ReadOnly))
		assert.Equal(testOpts, opts)

		testOpts = getDefaultOptions()
		opts = getOpts(WithFileAccessMode(WriteOnly))
		testOpts.withFileAccessMode = WriteOnly
		assert.Equal(opts, testOpts)

		testOpts = getDefaultOptions()
		opts = getOpts(WithFileAccessMode(ReadWrite))
		testOpts.withFileAccessMode = ReadWrite
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCreateFile", func(t *testing.T) {
		testOpts := getDefaultOptions()
		opts := getOpts()
		testOpts.withCreateFile = false
		assert.Equal(testOpts, opts)

		testOpts = getDefaultOptions()
		opts = getOpts(WithCreateFile())
		testOpts.withCreateFile = true
		assert.Equal(opts, testOpts)
	})
}
