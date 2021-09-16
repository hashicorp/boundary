package credential

import "encoding/json"

const (
	redactedPassword   = "[REDACTED: password]"
	redactedPrivateKey = "[REDACTED: private key]"
)

// String returns a string with the password redacted.
func (s Password) String() string {
	return redactedPassword
}

// GoString returns a string with the password redacted.
func (s Password) GoString() string {
	return redactedPassword
}

// MarshalJSON returns a JSON-encoded string with the password redacted.
func (s Password) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedPassword)
}

// String returns a string with the private key redacted.
func (s PrivateKey) String() string {
	return redactedPrivateKey
}

// GoString returns a string with the private key redacted.
func (s PrivateKey) GoString() string {
	return redactedPrivateKey
}

// MarshalJSON returns a JSON-encoded byte slice with the private key
// redacted.
func (s PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal([]byte(redactedPrivateKey))
}
