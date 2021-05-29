package node

import (
	"crypto/ed25519"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
)

// derivedKeyPurpose represents the purpose of the derived key.
type derivedKeyPurpose uint

const (
	derivedKeyPurposeUnknown = iota
	derivedKeyPurposeEvent
)

// String returns a representative string for the key's purpose
func (k derivedKeyPurpose) String() string {
	switch k {
	case derivedKeyPurposeEvent:
		return "event"
	default:
		return "unknown"
	}
}

// WrapperPayload defines an interface for eventlogger payloads which include
// wrapping.Wrapper fields.  This interface allows the AuditEncryptFilter to
// support per event wrappers and hmac salt/info.
type WrapperPayload interface {

	// Wrapper to use for the event encryption or hmac-sha256 operations
	Wrapper() wrapping.Wrapper

	// Event ID to use when deriving keys for crypto operatons on the event payload
	EventId() string

	// HmacSalt to use for the event hmac-sha256 operations
	HmacSalt() []byte

	// HmacInfo to use for the event hmac-sha256 operations
	HmacInfo() []byte
}

// NewEventWrapper is used by the AuditEncryptFilter to derive a wrapper to use
// for a specific event.  The event must implement the WrapperPayload interface
// for per event wrappers to be derived.
func NewEventWrapper(payloadWrapper wrapping.Wrapper, eventId string) (wrapping.Wrapper, error) {
	const op = "node.deriveWrapper"

	keyId := derivedKeyId(derivedKeyPurposeEvent, payloadWrapper.KeyID(), eventId)

	reader, err := kms.NewDerivedReader(payloadWrapper, 32, []byte(eventId), nil)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	privKey, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, errors.New(errors.Encrypt, op, "unable to generate key", errors.WithWrap(err))
	}
	derivedWrapper := aead.NewWrapper(nil)
	if _, err := derivedWrapper.SetConfig(map[string]string{
		"key_id": keyId,
	}); err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("error setting config on aead wrapper for event id %s", eventId)))
	}
	if err := derivedWrapper.SetAESGCMKeyBytes(privKey); err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("error setting key bytes on aead wrapper for event id %s", eventId)))
	}
	return payloadWrapper, nil
}

// derivedKeyId returns a key that represents the derived key
func derivedKeyId(purpose derivedKeyPurpose, wrapperKeyId, authMethodId string) string {
	return fmt.Sprintf("%s.%s.%s", purpose.String(), wrapperKeyId, authMethodId)
}
