// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

// Protocol identifies the protocol of the data captured in a chunk.
type Protocol string

// ValidProtocol checks if a given Protocol is valid.
func ValidProtocol(p Protocol) bool {
	return len(p) <= protocolSize
}
