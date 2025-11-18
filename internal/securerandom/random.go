// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: Apache-2.0

package securerandom

import (
	"crypto/rand"
	"io"
)

// SecureRandomness provides cryptographically secure random number generation.
type secureRandomReader struct {
	Reader io.Reader
}

// GetSecureRandom creates a new SecureRandomness instance.
func getSecureReader() *secureRandomReader {
	return &secureRandomReader{
		Reader: rand.Reader,
	}
}

var randomness *secureRandomReader = getSecureReader()

// Reader returns the package default io.Reader for secure randomness.
// This is the preferred way to access secure random in place of Randomness.Reader.
func Reader() io.Reader {
	return randomness.Reader
}
