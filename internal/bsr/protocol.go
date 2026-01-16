// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

// Protocol identifies the protocol of the data captured in a chunk.
type Protocol string

// ValidProtocol checks if a given Protocol is valid.
func ValidProtocol(p Protocol) bool {
	return len(p) <= protocolSize
}
