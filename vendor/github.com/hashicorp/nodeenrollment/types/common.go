// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"crypto/ecdh"
	"fmt"

	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/proto"
)

// ValidateMessage contains some common functions that can be used to ensure
// that the message is valid before further processing:
//
// * It's not nil
// * It's a known type
func ValidateMessage(msg proto.Message) error {
	const op = "nodeenrollment.ValidateMessage"
	if nodeenrollment.IsNil(msg) {
		return fmt.Errorf("(%s) nil message passed in to validate", op)
	}
	switch t := msg.(type) {
	case *NodeCredentials,
		*NodeInformation,
		*RootCertificates,
		*ServerLedActivationToken:
		// This should never be an issue as the compiler should catch it, but
		// just an extra check...
		if _, ok := t.(nodeenrollment.MessageWithId); !ok {
			return fmt.Errorf("(%s) message does not satisfy MessageWithId", op)
		}
	default:
		return fmt.Errorf("(%s) unknown message type %T", op, t)
	}
	return nil
}

// X25519EncryptionKey takes in public and private keys and performs the X25519
// operation on them.
//
// NOTE: This function is tested by tests on the individual implementations in
// NodeCredentials and NodeInformation, which also perform nil checks, and which
// are a thin wrapper around this.
func X25519EncryptionKey(privKey []byte, privKeyType KEYTYPE, pubKey []byte, pubKeyType KEYTYPE) ([]byte, error) {
	const op = "nodeenrollment.X25519EncryptionKey"
	switch {
	case len(privKey) == 0:
		return nil, fmt.Errorf("(%s) private key bytes is empty", op)
	case privKeyType != KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) private key type is not known", op)
	case len(pubKey) == 0:
		return nil, fmt.Errorf("(%s) public key bytes is empty", op)
	case pubKeyType != KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) public key type is not known", op)
	}

	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing public key: %w", op, err)
	}
	priv, err := curve.NewPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}

	out, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("(%s) error performing x25519 operation: %w", op, err)
	}

	return out, nil
}
