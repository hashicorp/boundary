// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

// ByteSource identifies whether bytes are flowing from the user to target (client)
// or target to user (server)
type ByteSource uint8

// ByteDirections
const (
	UnknownByteSource ByteSource = iota
	Client
	Server
)

func (d ByteSource) String() string {
	switch d {
	case Client:
		return "client"
	case Server:
		return "server"
	default:
		return "unknown bytesource"
	}
}

// ValidByteSource checks if a given ByteSource is valid.
func ValidByteSource(d ByteSource) bool {
	switch d {
	case Client, Server:
		return true
	}
	return false
}
