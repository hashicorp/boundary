// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientassertion

import (
	"fmt"
)

// KeyIDHeader is the "kid" header on a JWT, which providers use to look up
// the right public key to verify the JWT.
const KeyIDHeader = "kid"

// Option configures the JWT
type Option func(*JWT) error

// WithKeyID sets the "kid" header that OIDC providers use to look up the
// public key to check the signed JWT
func WithKeyID(keyID string) Option {
	const op = "WithKeyID"
	return func(j *JWT) error {
		if keyID == "" {
			return fmt.Errorf("%s: %w", op, ErrMissingKeyID)
		}
		j.headers[KeyIDHeader] = keyID
		return nil
	}
}

// WithHeaders sets extra JWT headers.
// Do not set a "kid" header here; instead use WithKeyID.
func WithHeaders(h map[string]string) Option {
	const op = "WithHeaders"
	return func(j *JWT) error {
		for k, v := range h {
			if k == KeyIDHeader {
				return fmt.Errorf("%s: %w", op, ErrKidHeader)
			}
			j.headers[k] = v
		}
		return nil
	}
}
