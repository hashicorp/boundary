// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ nodeenrollment.X25519KeyProducer = (*NodeCredentials)(nil)

// Store stores node credentials to storage, wrapping values along the way if
// given a wrapper
//
// Supported options: WithStorageWrapper
func (n *NodeCredentials) Store(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) error {
	const op = "nodeenrollment.types.(NodeCredentials).Store"

	switch {
	case nodeenrollment.IsNil(storage):
		return fmt.Errorf("(%s) storage is nil", op)

	case nodeenrollment.IsNil(n):
		return fmt.Errorf("(%s) node credentials is nil", op)

	case len(n.CertificatePrivateKeyPkcs8) == 0:
		return fmt.Errorf("(%s) refusing to store node credentials with no certificate pkcs8 private key", op)

	case len(n.CertificatePublicKeyPkix) == 0:
		// This isn't really a validation function, but we want to avoid
		// wrapping with nil AAD so we do a check here
		return fmt.Errorf("(%s) refusing to store node credentials with no certificate pkix public key", op)

	case len(n.EncryptionPrivateKeyBytes) == 0:
		return fmt.Errorf("(%s) refusing to store node credentials with no encryption private key", op)

	case n.Id == "":
		return fmt.Errorf("(%s) missing id", op)
	}

	switch nodeenrollment.KnownId(n.Id) {
	case nodeenrollment.MissingId:
		return fmt.Errorf("(%s) credentials is missing id", op)
	case nodeenrollment.CurrentId, nodeenrollment.NextId:
	default:
		return fmt.Errorf("(%s) invalid node credentials id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	credsToStore := n
	if opts.WithStorageWrapper != nil {
		credsToStore = proto.Clone(n).(*NodeCredentials)

		keyId, err := opts.WithStorageWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		credsToStore.WrappingKeyId = keyId

		blobInfo, err := opts.WithStorageWrapper.Encrypt(
			ctx,
			credsToStore.CertificatePrivateKeyPkcs8,
			wrapping.WithAad(credsToStore.CertificatePublicKeyPkix),
		)
		if err != nil {
			return fmt.Errorf("(%s) error wrapping certificate private key: %w", op, err)
		}
		credsToStore.CertificatePrivateKeyPkcs8, err = proto.Marshal(blobInfo)
		if err != nil {
			return fmt.Errorf("(%s) error marshaling wrapped certificate private key: %w", op, err)
		}

		blobInfo, err = opts.WithStorageWrapper.Encrypt(
			ctx,
			credsToStore.EncryptionPrivateKeyBytes,
			wrapping.WithAad(credsToStore.CertificatePublicKeyPkix),
		)
		if err != nil {
			return fmt.Errorf("(%s) error wrapping encryption private key: %w", op, err)
		}
		credsToStore.EncryptionPrivateKeyBytes, err = proto.Marshal(blobInfo)
		if err != nil {
			return fmt.Errorf("(%s) error marshaling wrapped encryption private key: %w", op, err)
		}

		if len(credsToStore.RegistrationNonce) != 0 {
			blobInfo, err = opts.WithStorageWrapper.Encrypt(
				ctx,
				credsToStore.RegistrationNonce,
				wrapping.WithAad(credsToStore.CertificatePublicKeyPkix),
			)
			if err != nil {
				return fmt.Errorf("(%s) error wrapping registration nonce: %w", op, err)
			}
			credsToStore.RegistrationNonce, err = proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling wrapped registration nonce: %w", op, err)
			}
		}
	}

	if err := storage.Store(ctx, credsToStore); err != nil {
		return fmt.Errorf("(%s) error storing node credentials: %w", op, err)
	}

	return nil
}

// LoadNodeCredentials loads the node credentials from storage, unwrapping
// encrypted values if needed
//
// Supported options: WithStorageWrapper
func LoadNodeCredentials(ctx context.Context, storage nodeenrollment.Storage, id nodeenrollment.KnownId, opt ...nodeenrollment.Option) (*NodeCredentials, error) {
	const op = "nodeenrollment.types.LoadNodeCredentials"

	if nodeenrollment.IsNil(storage) {
		return nil, fmt.Errorf("(%s) storage is nil", op)
	}

	switch nodeenrollment.KnownId(id) {
	case nodeenrollment.MissingId:
		return nil, fmt.Errorf("(%s) credentials is missing id", op)
	case nodeenrollment.CurrentId, nodeenrollment.NextId:
	default:
		return nil, fmt.Errorf("(%s) invalid node credentials id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeCreds := &NodeCredentials{
		Id: string(id),
	}
	if err := storage.Load(ctx, nodeCreds); err != nil {
		return nil, fmt.Errorf("(%s) error loading node credentials from storage: %w", op, err)
	}

	switch {
	case opts.WithStorageWrapper == nil && nodeCreds.WrappingKeyId != "":
		return nil, fmt.Errorf("(%s) node credentials has encrypted parts with wrapper key id %q but wrapper not provided", op, nodeCreds.WrappingKeyId)
	case nodeCreds.WrappingKeyId != "":
		// Note: not checking the wrapper key IDs against each other because if
		// using something like a PooledWrapper then the current encryping ID
		// may not match, or if the wrapper performs its own internal key
		// selection.
		blobInfo := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(nodeCreds.CertificatePrivateKeyPkcs8, blobInfo); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling certificate private key blob info: %w", op, err)
		}
		pt, err := opts.WithStorageWrapper.Decrypt(
			ctx,
			blobInfo,
			wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
		)
		if err != nil {
			return nil, fmt.Errorf("(%s) error decrypting certificate private key: %w", op, err)
		}
		nodeCreds.CertificatePrivateKeyPkcs8 = pt

		blobInfo = new(wrapping.BlobInfo)
		if err := proto.Unmarshal(nodeCreds.EncryptionPrivateKeyBytes, blobInfo); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling encryption private key blob info: %w", op, err)
		}
		pt, err = opts.WithStorageWrapper.Decrypt(
			ctx,
			blobInfo,
			wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
		)
		if err != nil {
			return nil, fmt.Errorf("(%s) error decrypting encryption private key: %w", op, err)
		}
		nodeCreds.EncryptionPrivateKeyBytes = pt

		if len(nodeCreds.RegistrationNonce) != 0 {
			blobInfo = new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeCreds.RegistrationNonce, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling registration nonce blob info: %w", op, err)
			}
			pt, err := opts.WithStorageWrapper.Decrypt(
				ctx,
				blobInfo,
				wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
			)
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting registration nonce: %w", op, err)
			}
			nodeCreds.RegistrationNonce = pt
		}

		nodeCreds.WrappingKeyId = ""
	}

	return nodeCreds, nil
}

// X25519EncryptionKey uses the NodeCredentials values to produce a shared
// encryption key via X25519
func (n *NodeCredentials) X25519EncryptionKey() (string, []byte, error) {
	const op = "nodeenrollment.types.(NodeCredentials).X25519EncryptionKey"
	if nodeenrollment.IsNil(n) {
		return "", nil, fmt.Errorf("(%s) node credentials is empty", op)
	}

	out, err := X25519EncryptionKey(n.EncryptionPrivateKeyBytes, n.EncryptionPrivateKeyType, n.ServerEncryptionPublicKeyBytes, n.ServerEncryptionPublicKeyType)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving encryption key: %w", op, err)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(n.CertificatePublicKeyPkix)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	return keyId, out, nil
}

// PreviousX25519EncryptionKey satisfies the X25519Producer and will produce a shared
// encryption key via X25519 if previous key data is present
func (n *NodeCredentials) PreviousX25519EncryptionKey() (string, []byte, error) {
	const op = "nodeenrollment.types.(NodeCredentials).PreviousX25519EncryptionKey"

	if nodeenrollment.IsNil(n) {
		return "", nil, fmt.Errorf("(%s) node credentials is empty", op)
	}

	previousKey := n.PreviousEncryptionKey
	if previousKey == nil {
		return "", nil, fmt.Errorf("(%s) previous key is empty", op)
	}

	out, err := X25519EncryptionKey(previousKey.PrivateKeyPkcs8, previousKey.PrivateKeyType, previousKey.PublicKeyPkix, previousKey.PublicKeyType)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving previous encryption key: %w", op, err)
	}

	return previousKey.KeyId, out, nil
}

// NewNodeCredentials creates a new node credentials object and populates it
// with suitable parameters for presenting for registration.
//
// Once registration succeeds, the node credentials stored here can be used to
// decrypt the incoming bundle with the server's view of the node credentials,
// which can then be merged; this happens in a different function.
//
// Supported options: WithRandomReader, WithStorageWrapper (passed through to
// NodeCredentials.Store), WithSkipStorage, WithActivationToken
func NewNodeCredentials(
	ctx context.Context,
	storage nodeenrollment.Storage,
	opt ...nodeenrollment.Option,
) (*NodeCredentials, error) {
	const op = "nodeenrollment.types.NewNodeCredentials"

	if nodeenrollment.IsNil(storage) {
		return nil, fmt.Errorf("(%s) storage is nil", op)
	}

	n := new(NodeCredentials)

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var (
		certPubKey  ed25519.PublicKey
		certPrivKey ed25519.PrivateKey
	)

	switch len(opts.WithActivationToken) {
	case 0:
		n.RegistrationNonce = make([]byte, nodeenrollment.NonceSize)
		num, err := opts.WithRandomReader.Read(n.RegistrationNonce)
		switch {
		case err != nil:
			return nil, fmt.Errorf("(%s) error generating nonce: %w", op, err)
		case num != nodeenrollment.NonceSize:
			return nil, fmt.Errorf("(%s) read incorrect number of bytes for nonce, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
		}
	default:
		nonce, err := base58.FastBase58Decoding(strings.TrimPrefix(opts.WithActivationToken, nodeenrollment.ServerLedActivationTokenPrefix))
		if err != nil {
			return nil, fmt.Errorf("(%s) error base58-decoding activation token: %w", op, err)
		}
		n.RegistrationNonce = nonce
	}

	// Create certificate keypair
	{
		certPubKey, certPrivKey, err = ed25519.GenerateKey(opts.WithRandomReader)
		if err != nil {
			return nil, fmt.Errorf("(%s) error generating certificate keypair: %w", op, err)
		}

		n.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(certPrivKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling certificate private key: %w", op, err)
		}
		n.CertificatePrivateKeyType = KEYTYPE_ED25519

		n.CertificatePublicKeyPkix, _, err = nodeenrollment.SubjectKeyInfoAndKeyIdFromPubKey(certPubKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error fetching public key id: %w", op, err)
		}
	}

	// Create node encryption keys
	{
		n.EncryptionPrivateKeyBytes = make([]byte, curve25519.ScalarSize)
		num, err := opts.WithRandomReader.Read(n.EncryptionPrivateKeyBytes)
		switch {
		case err != nil:
			return nil, fmt.Errorf("(%s) error reading random bytes to generate node encryption key: %w", op, err)
		case num != curve25519.ScalarSize:
			return nil, fmt.Errorf("(%s) wrong number of random bytes read when generating node encryption key, expected %d but got %d", op, curve25519.ScalarSize, num)
		}
		n.EncryptionPrivateKeyType = KEYTYPE_X25519
	}

	n.Id = string(nodeenrollment.CurrentId)
	if !opts.WithSkipStorage {
		if err := n.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) failed to store generated node creds: %w", op, err)
		}
	}

	return n, nil
}

// SetPreviousEncryptionKey will set this NodeCredential's PreviousEncryptionKey field
// using the passed NodeCredentials
func (n *NodeCredentials) SetPreviousEncryptionKey(oldNodeCredentials *NodeCredentials) error {
	const op = "nodeenrollment.types.(NodeCredentials).SetPreviousEncryptionKey"
	if oldNodeCredentials == nil {
		return fmt.Errorf("(%s) empty prior credentials passed in", op)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(oldNodeCredentials.CertificatePublicKeyPkix)
	if err != nil {
		return fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}
	previousEncryptionKey := &EncryptionKey{
		KeyId:           keyId,
		PrivateKeyPkcs8: oldNodeCredentials.EncryptionPrivateKeyBytes,
		PrivateKeyType:  oldNodeCredentials.EncryptionPrivateKeyType,
		PublicKeyPkix:   oldNodeCredentials.ServerEncryptionPublicKeyBytes,
		PublicKeyType:   oldNodeCredentials.ServerEncryptionPublicKeyType,
	}
	n.PreviousEncryptionKey = previousEncryptionKey

	return nil
}

// CreateFetchNodeCredentialsRequest creates and returns a fetch request based
// on the current node creds
//
// Supported options: WithRandomReader, WithActivationToken (used in place of
// the node's nonce value if provided, for the server-led flow; note that this
// should be the full string token, it will be decoded by this function),
// WithRegistrationWrapper/WithWrappingRegistrationFlowApplicationSpecificParams
func (n *NodeCredentials) CreateFetchNodeCredentialsRequest(
	ctx context.Context,
	opt ...nodeenrollment.Option,
) (*FetchNodeCredentialsRequest, error) {
	const op = "nodeenrollment.types.(NodeCredentials).CreateFetchNodeCredentialsRequest"

	switch {
	case nodeenrollment.IsNil(n):
		return nil, fmt.Errorf("(%s) node credentials is nil", op)
	case len(n.CertificatePrivateKeyPkcs8) == 0:
		return nil, fmt.Errorf("(%s) node credentials pkcs8 private key is empty", op)
	case len(n.CertificatePublicKeyPkix) == 0:
		return nil, fmt.Errorf("(%s) node credentials pkix public key is empty", op)
	case len(n.RegistrationNonce) == 0:
		return nil, fmt.Errorf("(%s) node credentials registration nonce is empty", op)
	case len(n.EncryptionPrivateKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) node credentials encryption private key is empty", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(n.CertificatePrivateKeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}

	now := time.Now()
	reqInfo := &FetchNodeCredentialsInfo{
		CertificatePublicKeyPkix:         n.CertificatePublicKeyPkix,
		CertificatePublicKeyType:         n.CertificatePrivateKeyType,
		PreviousCertificatePublicKeyPkix: n.PreviousCertificatePublicKeyPkix,
		Nonce:                            n.RegistrationNonce,
		EncryptionPublicKeyType:          KEYTYPE_X25519,
		NotBefore:                        timestamppb.New(now),
		NotAfter:                         timestamppb.New(now.Add(nodeenrollment.DefaultFetchCredentialsLifetime)),
	}

	switch {
	case !nodeenrollment.IsNil(opts.WithRegistrationWrapper):
		// Create an encrypted registration request
		regInfo := &WrappingRegistrationFlowInfo{
			CertificatePublicKeyPkix:  n.CertificatePublicKeyPkix,
			Nonce:                     n.RegistrationNonce,
			ApplicationSpecificParams: opts.WithWrappingRegistrationFlowApplicationSpecificParams,
		}
		regInfoBytes, err := proto.Marshal(regInfo)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling wrapping flow registration info: %w", op, err)
		}
		blobInfo, err := opts.WithRegistrationWrapper.Encrypt(ctx, regInfoBytes)
		if err != nil {
			return nil, fmt.Errorf("(%s) error encrypting wrapping flow registration info: %w", op, err)
		}
		encryptedRegInfo, err := proto.Marshal(blobInfo)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling encrypted wrapping flow registration info: %w", op, err)
		}
		reqInfo.WrappedRegistrationInfo = encryptedRegInfo

	case opts.WithActivationToken != "":
		nonce, err := base58.FastBase58Decoding(strings.TrimPrefix(opts.WithActivationToken, nodeenrollment.ServerLedActivationTokenPrefix))
		if err != nil {
			return nil, fmt.Errorf("(%s) error base58-decoding activation token: %w", op, err)
		}
		reqInfo.Nonce = nonce
	}

	encryptionPrivateKey, err := ecdh.X25519().NewPrivateKey(n.EncryptionPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("(%s) error reading node private encryption key: %w", op, err)
	}
	reqInfo.EncryptionPublicKeyBytes = encryptionPrivateKey.PublicKey().Bytes()

	var req FetchNodeCredentialsRequest
	req.Bundle, err = proto.Marshal(reqInfo)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling fetch node credentials info: %w", op, err)
	}

	sigBytes, err := privKey.(crypto.Signer).Sign(opts.WithRandomReader, req.Bundle, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("(%s) error signing request data message: %w", op, err)
	}
	req.BundleSignature = sigBytes

	return &req, nil
}

// HandleFetchNodeCredentialsResponse parses the response from a server for node
// credentials and attempts to decrypt and merge with the existing
// NodeCredentials, storing the result. It returns the updated value and any
// error and stores the result in storage, unless WithSkipStorage is passed.
//
// Supported options: WithWrapping (passed through to NodeCredentials.Store),
// WithSkipStorage, WithActivationToken (overrides the NodeCredentials' nonce
// when using server-led node authorization)
func (n *NodeCredentials) HandleFetchNodeCredentialsResponse(
	ctx context.Context,
	storage nodeenrollment.Storage,
	input *FetchNodeCredentialsResponse,
	opt ...nodeenrollment.Option,
) (*NodeCredentials, error) {
	const op = "nodeenrollment.types.(NodeCredentials).HandleFetchNodeCredentialsResponse"

	switch {
	case n == nil:
		return nil, fmt.Errorf("(%s) node credentials is nil", op)
	case input == nil:
		return nil, fmt.Errorf("(%s) input is nil", op)
	case len(input.EncryptedNodeCredentials) == 0:
		return nil, fmt.Errorf("(%s) input encrypted node credentials is nil", op)
	case len(input.ServerEncryptionPublicKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) server encryption public key bytes is nil", op)
	case input.ServerEncryptionPublicKeyType != KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) server encryption public key type is unknown", op)
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	n.ServerEncryptionPublicKeyBytes = input.ServerEncryptionPublicKeyBytes
	n.ServerEncryptionPublicKeyType = input.ServerEncryptionPublicKeyType

	newNodeCreds := new(NodeCredentials)
	if err := nodeenrollment.DecryptMessage(
		ctx,
		input.EncryptedNodeCredentials,
		n,
		newNodeCreds,
		opt...,
	); err != nil {
		return nil, fmt.Errorf("(%s) error decrypting server message: %w", op, err)
	}

	// Validate the nonce
	nonce := n.RegistrationNonce
	if opts.WithActivationToken != "" {
		nonce, err = base58.FastBase58Decoding(strings.TrimPrefix(opts.WithActivationToken, nodeenrollment.ServerLedActivationTokenPrefix))
		if err != nil {
			return nil, fmt.Errorf("(%s) error base58-decoding activation token: %w", op, err)
		}
	}
	if subtle.ConstantTimeCompare(nonce, newNodeCreds.RegistrationNonce) == 0 {
		return nil, fmt.Errorf("(%s) server message decrypted successfully but nonce does not match", op)
	}
	n.RegistrationNonce = nil

	// Now copy values over
	n.CertificateBundles = newNodeCreds.CertificateBundles

	n.Id = string(nodeenrollment.CurrentId)
	if !opts.WithSkipStorage {
		if err := n.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) failed to store updated node creds: %w", op, err)
		}
	}

	return n, nil
}
