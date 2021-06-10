package vault

import (
	"encoding/json"
)

// TokenSecret equals a Vault token.  This type provides a
// wrapper so the secret isn't inadvertently leaked into a log or error.
type TokenSecret []byte

// redactedTokenSecret is the redacted string or json for an Vault token.
const redactedTokenSecret = "[REDACTED: Vault token_secret]"

// String will redact the TokenSecret.
func (s TokenSecret) String() string {
	return redactedTokenSecret
}

// GoString will redact the TokenSecret.
func (s TokenSecret) GoString() string {
	return redactedTokenSecret
}

// MarshalJSON will redact the TokenSecret.
func (s TokenSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal([]byte(redactedTokenSecret))
}
