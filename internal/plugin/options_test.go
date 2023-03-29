// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		opts := GetOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := GetOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithPublicId", func(t *testing.T) {
		opts := GetOpts(WithPublicId("pl_1234567890"))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = "pl_1234567890"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts := GetOpts(WithLimit(5))
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		assert.Equal(t, opts, testOpts)
	})
}
