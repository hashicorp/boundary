// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

const (
	// ChannelIdPrefix is the prefix for the channel recording id.
	ChannelIdPrefix = globals.ChannelRecordingPrefix
)

// NewChannelId generates an id for a channel recording.
func NewChannelId() (string, error) {
	const op = "bsr.NewChannelId"

	var publicId string
	var err error

	publicId, err = base62.Random(10)
	if err != nil {
		return "", fmt.Errorf("%s: unable to generate id: %w", op, err)
	}
	return fmt.Sprintf("%s_%s", ChannelIdPrefix, publicId), nil
}
