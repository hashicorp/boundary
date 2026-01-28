// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_getOpts provides unit tests for GetOpts and all the options
func Test_getOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithCloseSyncMode", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		opts := GetOpts(WithCloseSyncMode(Asynchronous))
		assert.Equal(testOpts, opts)

		testOpts = getDefaultOptions()
		opts = GetOpts(WithCloseSyncMode(Synchronous))
		testOpts.WithCloseSyncMode = Synchronous
		assert.Equal(opts, testOpts)

		testOpts = getDefaultOptions()
		opts = GetOpts(WithCloseSyncMode(NoSync))
		testOpts.WithCloseSyncMode = NoSync
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFileAccessMode", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		opts := GetOpts(WithFileAccessMode(ReadOnly))
		assert.Equal(testOpts, opts)

		testOpts = getDefaultOptions()
		opts = GetOpts(WithFileAccessMode(WriteOnly))
		testOpts.WithFileAccessMode = WriteOnly
		assert.Equal(opts, testOpts)

		testOpts = getDefaultOptions()
		opts = GetOpts(WithFileAccessMode(ReadWrite))
		testOpts.WithFileAccessMode = ReadWrite
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCreateFile", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		opts := GetOpts()
		testOpts.WithCreateFile = false
		assert.Equal(testOpts, opts)

		testOpts = getDefaultOptions()
		opts = GetOpts(WithCreateFile())
		testOpts.WithCreateFile = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithBuffer", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		opts := GetOpts(WithBuffer(0))
		assert.Equal(testOpts, opts)

		testOpts = getDefaultOptions()
		opts = GetOpts(WithBuffer(4096))
		testOpts.WithBuffer = 4096
		assert.Equal(opts, testOpts)
	})

	t.Run("WithMinimumAvailableDiskSpace", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)
		testOpts := getDefaultOptions()
		opts := GetOpts()
		assert.Equal(testOpts, opts)

		testOpts = getDefaultOptions()
		opts = GetOpts(WithMinimumAvailableDiskSpace(4096))
		testOpts.WithMinimumAvailableDiskSpace = 4096
		assert.Equal(opts, testOpts)
	})
}
