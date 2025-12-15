// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithChannelId", func(t *testing.T) {
		assert := assert.New(t)
		channelId := "channel-id"
		opts := getOpts(WithChannelId(channelId))
		testOpts := getDefaultOptions()
		testOpts.withChannelId = channelId
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMinWidth", func(t *testing.T) {
		assert := assert.New(t)
		width := uint32(23)
		opts := getOpts(WithMinWidth(width))
		testOpts := getDefaultOptions()
		testOpts.withMinWidth = width
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMinHeight", func(t *testing.T) {
		assert := assert.New(t)
		height := uint32(64)
		opts := getOpts(WithMinHeight(height))
		testOpts := getDefaultOptions()
		testOpts.withMinHeight = height
		assert.Equal(opts, testOpts)
	})
}
