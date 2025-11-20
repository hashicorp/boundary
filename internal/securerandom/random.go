// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: Apache-2.0

package securerandom

import (
	"crypto/rand"
	"io"
)

// secureRandom provides cryptographically secure random number generation.
type secureRandom struct {
	Reader io.Reader
}

// getSecureRandom creates a new secureRandom instance.
func getSecureReader() *secureRandom {
	return &secureRandom{
		Reader: rand.Reader,
	}
}

var readRandom *secureRandom = getSecureReader()

// SecureRandomReader returns the package default io.Reader for secure randomness.
func SecureRandomReader() io.Reader {
	return readRandom.Reader
}
