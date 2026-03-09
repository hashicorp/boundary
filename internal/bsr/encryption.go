// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

const (
	encryptionSize = 1
)

// Encryption is used to identify the encryption used for the data in chunks.
type Encryption uint8

// Supported encryption methods.
const (
	NoEncryption Encryption = iota
)

func (e Encryption) String() string {
	switch e {
	case NoEncryption:
		return "no encryption"
	default:
		return "unknown encryption"
	}
}

// ValidEncryption checks if a given Encryption is valid.
func ValidEncryption(e Encryption) bool {
	switch e {
	case NoEncryption:
		return true
	}
	return false
}
