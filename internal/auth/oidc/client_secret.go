package oidc

import (
	"encoding/json"
)

type ClientSecret string

// RedactedClientSecret is the redacted string or json for an oidc id_token.
const redactedClientSecret = "[REDACTED: OIDC client_secret]"

// String will redact the client_secret.
func (s ClientSecret) String() string {
	return redactedClientSecret
}

// MarshalJSON will redact the client_secret.
func (s ClientSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedClientSecret)
}
