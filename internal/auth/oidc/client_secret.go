// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"encoding/json"
)

// ClientSecret equals an AuthMethod's client secret.  This type provides a
// wrapper so the secret isn't inadvertently leaked into a log or error.
type ClientSecret string

// RedactedClientSecret is the redacted string or json for an oidc id_token.
const redactedClientSecret = "[REDACTED: OIDC client_secret]"

// String will redact the client_secret.
func (s ClientSecret) String() string {
	return redactedClientSecret
}

// GoString will redact the client_secret.
func (s ClientSecret) GoString() string {
	return redactedClientSecret
}

// MarshalJSON will redact the client_secret.
func (s ClientSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedClientSecret)
}
