// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		opts, err := getOpts()
		assert.NoError(t, err)
		testOpts := options{}
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOutputCurlString", func(t *testing.T) {
		opts, err := getOpts(WithOutputCurlString())
		assert.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withOutputCurlString = true
		assert.Equal(t, opts, testOpts)
	})
}
