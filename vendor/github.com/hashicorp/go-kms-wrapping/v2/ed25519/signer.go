// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ed25519

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"golang.org/x/exp/slices"
)

// Signer provides an ed25519 implementation for the wrapping.Signer interface
type Signer struct {
	privKey     ed25519.PrivateKey
	keyId       string
	keyPurposes []wrapping.KeyPurpose
	keyType     wrapping.KeyType
}

var _ wrapping.SigInfoSigner = (*Signer)(nil)
var _ wrapping.KeyExporter = (*Signer)(nil)

// NewSigner creates a new Signer.   Supported options: WithKeyId,
// WithKeyPurposes, WithPrivKey, WithConfigMap
//
// Note: options order of precedence is: local options, WithConfigMap provided
// options and finally wrapping options.
func NewSigner(ctx context.Context, opt ...wrapping.Option) (*Signer, error) {
	const op = "ed25519.NewSigner"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if len(opts.WithKeyPurposes) == 0 {
		opts.WithKeyPurposes = append(opts.WithKeyPurposes, wrapping.KeyPurpose_Sign)
	}
	return &Signer{
		privKey:     opts.WithPrivKey,
		keyId:       opts.WithKeyId,
		keyPurposes: opts.WithKeyPurposes,
		keyType:     wrapping.KeyType_Ed25519,
	}, nil
}

// SetConfig sets the fields on the Signer
//
// Supported options: wrapping.WithKeyId, wrapping.WithKeyPurposes,
// wrapping.WithConfigMap and the local WithPrivKey
//
// Note: options order of precedence is: local options, WithConfigMap provided
// options and finally wrapping options.
//
// wrapping.WithConfigMap supports a ConfigPrivKey to set the Signer priv key
// along with ConfigKeyId, and ConfigKeyPurposes.  ConfigKeyPurposes are a
// comma delimited list of wrapping.KeyPurpose_name values (for example:
// "Sign, Verify")
//
// The values in WithConfigMap can also be set via the package's native local
// options.
func (s *Signer) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	const op = "ed25519.(Signer).SetConfig"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	switch {
	case len(opts.WithPrivKey) == 0:
		return nil, fmt.Errorf("%s: missing private key: %w", op, wrapping.ErrInvalidParameter)
	case len(opts.WithKeyPurposes) == 0:
		return nil, fmt.Errorf("%s: missing key purposes: %w", op, wrapping.ErrInvalidParameter)
	}

	s.keyId = opts.WithKeyId
	s.keyPurposes = opts.WithKeyPurposes
	s.privKey = opts.WithPrivKey

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)

	return wrapConfig, nil
}

// Sign creates a signature of the provided msg.  No options are currently supported.
func (s *Signer) Sign(tx context.Context, msg []byte, _ ...wrapping.Option) (*wrapping.SigInfo, error) {
	const op = "ed25519.(Ed25519Signer).Sign"
	switch {
	case s.privKey == nil:
		return nil, fmt.Errorf("%s: missing private key: %w", op, wrapping.ErrInvalidParameter)
	case msg == nil:
		return nil, fmt.Errorf("%s: missing message: %w", op, wrapping.ErrInvalidParameter)
	case len(s.keyPurposes) > 0 && !slices.Contains(s.keyPurposes, wrapping.KeyPurpose_Sign):
		supportedPurposes := make([]string, 0, len(s.keyPurposes))
		for _, p := range s.keyPurposes {
			supportedPurposes = append(supportedPurposes, wrapping.KeyPurpose_name[int32(p)])
		}
		return nil,
			fmt.Errorf(
				"%s: key's supported purposes %q does not contain %s: %w",
				op,
				strings.Join(supportedPurposes, ", "),
				wrapping.KeyPurpose_name[int32(wrapping.KeyPurpose_Sign)],
				wrapping.ErrInvalidParameter,
			)
	}
	// intentionally passing in a nil rand reader since it's not required... and
	// if that changes we want a panic in the unit tests
	sig, err := s.privKey.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("%s: signing error: %w", op, err)
	}
	return &wrapping.SigInfo{
		Signature: sig,
		KeyInfo: &wrapping.KeyInfo{
			KeyType:     wrapping.KeyType_Ed25519,
			KeyId:       s.keyId,
			KeyPurposes: s.keyPurposes,
		},
	}, nil
}

// KeyBytes returns the current key bytes
func (s *Signer) KeyBytes(context.Context) ([]byte, error) {
	const op = "ed25519.(Signer).KeyBytes"
	if s.privKey == nil {
		return nil, fmt.Errorf("%s: missing bytes: %w", op, wrapping.ErrInvalidParameter)
	}
	return s.privKey, nil
}
