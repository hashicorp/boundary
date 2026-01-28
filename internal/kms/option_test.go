// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
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
	t.Run("WithOrderByVersion", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithOrderByVersion(db.DescendingOrderBy))
		testOpts := getDefaultOptions()
		testOpts.withOrderByVersion = db.DescendingOrderBy
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithKeyId("100"))
		testOpts := getDefaultOptions()
		testOpts.withKeyId = "100"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRewrap", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithRewrap(true))
		testOpts := getDefaultOptions()
		testOpts.withRewrap = true
		assert.Equal(opts, testOpts)
	})
}
