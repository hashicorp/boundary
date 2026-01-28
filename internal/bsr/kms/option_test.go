// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("WithRandomReader", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithRandomReader(rand.Reader))
		testOpts := getDefaultOptions()
		testOpts.withRandomReader = rand.Reader
		assert.Equal(opts, testOpts)
	})
}
