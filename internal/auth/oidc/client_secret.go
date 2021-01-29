package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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

// HMAC returns a value suitable for read operations like API GETs, when a read
// only representative value is needed (ie Terraform operations)
func (s ClientSecret) HMAC(derivedKey []byte) string {
	mac := hmac.New(sha256.New, derivedKey)
	_, _ = mac.Write([]byte(s))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}
