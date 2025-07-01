// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// TestSigInfo creates a test SigInfo using the provided ed25519 priv key
func TestSigInfo(t *testing.T, privKey ed25519.PrivateKey, msg []byte, opt ...wrapping.Option) *wrapping.SigInfo {
	t.Helper()
	require := require.New(t)
	sig, err := privKey.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(err)
	opts, err := wrapping.GetOpts(opt...)
	require.NoError(err)

	return &wrapping.SigInfo{
		Signature: sig,
		KeyInfo: &wrapping.KeyInfo{
			KeyType:     wrapping.KeyType_Ed25519,
			KeyId:       opts.WithKeyId,
			KeyPurposes: opts.WithKeyPurposes,
		},
	}
}
