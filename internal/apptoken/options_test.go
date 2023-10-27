// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getOpts(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("WithName", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithName(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithDescription(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withDescription = "test"
		assert.Equal(opts, testOpts)
	})
}
