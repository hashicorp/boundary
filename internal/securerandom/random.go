// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: Apache-2.0

package securerandom

import (
	"crypto/rand"
	"io"
)

// SecureRandomness provides cryptographically secure random number generation.
type SecureRandomness struct {
	SecureRandomReader io.Reader
}

// NewSecureRandom creates a new SecureRandomness instance.
func GetSecureReader() *SecureRandomness {
	return &SecureRandomness{
		SecureRandomReader: rand.Reader,
	}
}
