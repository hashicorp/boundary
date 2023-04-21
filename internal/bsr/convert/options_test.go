// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
}
