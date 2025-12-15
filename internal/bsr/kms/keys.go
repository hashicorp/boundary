// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/boundary/internal/util"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	wrappingEd "github.com/hashicorp/go-kms-wrapping/v2/ed25519"

	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
	"google.golang.org/protobuf/proto"
)

// Keys are the keys required/associated with a BSR for crypto operations.
//
// Operations on this type are concurrently safe.
type Keys struct {
	// WrappedBsrKey is the "bsr key" which is a wrapped AES-GCM key
	WrappedBsrKey *wrapping.KeyInfo

	// WrappedPrivKey is the BSR's wrapped ed25519.PrivateKey
	WrappedPrivKey *wrapping.KeyInfo

	// BsrKey is the plaintext "bsr key" which is an AES-GCM key
	BsrKey *wrapping.KeyInfo

	// PrivKey is the BSR's plaintext ed25519.PrivateKey
	PrivKey *wrapping.KeyInfo

	// PubKey is the BSR's plaintext ed25519.PublicKey
	PubKey *wrapping.KeyInfo

	// PubKeySelfSignature is a self-signature of the BSR's plaintext
	// ed25519.PublicKey created with its ed25519.PrivateKey
	PubKeySelfSignature *wrapping.SigInfo

	// PubKeyBsrSignature is a signature of the BSR's plaintext ed25519.Public
	// key created with the BsrKey (AES-GCM)
	PubKeyBsrSignature *wrapping.SigInfo

	l sync.RWMutex
}

// WrappedKeys contains the wrapped BSR and priv keys
type WrappedKeys struct {
	WrappedBsrKey  *wrapping.KeyInfo
	WrappedPrivKey *wrapping.KeyInfo
}

// Unwrapped keys contains the unwrapped BSR and priv keys
type UnwrappedKeys struct {
	BsrKey  *wrapping.KeyInfo
	PrivKey *wrapping.KeyInfo
}

// KeyUnwrapCallbackFunc is used by OpenSession to unwrap BSR and private keys
type KeyUnwrapCallbackFunc func(WrappedKeys) (UnwrappedKeys, error)

// CreateKeys creates new bsr keys, wrapping and signing keys as required
// using the provided bsrWrapper. Supported options: WithRandomReader
func CreateKeys(ctx context.Context, bsrWrapper wrapping.Wrapper, sessionId string, opt ...Option) (*Keys, error) {
	const op = "kms.CreateBsrKeys"
	switch {
	case sessionId == "":
		return nil, fmt.Errorf("%s: missing session id: %w", op, ErrInvalidParameter)
	case is.Nil(bsrWrapper):
		return nil, fmt.Errorf("%s: missing external bsr wrapper: %w", op, ErrInvalidParameter)
	}

	opts := getOpts(opt...)

	if opts.withRandomReader == nil {
		opts.withRandomReader = rand.Reader
	}

	retKeys := &Keys{}

	bsrKey := make([]byte, 32)
	n, err := opts.withRandomReader.Read(bsrKey)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: error reading random bytes for bsr: %w", op, ErrGenKey)
	case n != 32:
		return nil, fmt.Errorf("%s: wanted 32 bytes and got %d: %w", op, n, ErrGenKey)
	}
	bsrBlob, err := bsrWrapper.Encrypt(ctx, bsrKey)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to encrypt bsr key: %w", op, ErrEncrypt)
	}
	marshaledBsrBlob, err := proto.Marshal(bsrBlob)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to marshal bsr key %w: %w", op, err, ErrEncode)
	}
	retKeys.WrappedBsrKey = &wrapping.KeyInfo{
		KeyId:       sessionId,
		WrappedKey:  marshaledBsrBlob,
		KeyType:     wrapping.KeyType_Aes256,
		KeyEncoding: wrapping.KeyEncoding_Bytes,
		KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign, wrapping.KeyPurpose_Encrypt, wrapping.KeyPurpose_Decrypt},
	}
	retKeys.BsrKey = &wrapping.KeyInfo{
		KeyId:       sessionId,
		Key:         bsrKey,
		KeyType:     wrapping.KeyType_Aes256,
		KeyEncoding: wrapping.KeyEncoding_Bytes,
		KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign, wrapping.KeyPurpose_Encrypt, wrapping.KeyPurpose_Decrypt},
	}

	pub, priv, err := ed25519.GenerateKey(opts.withRandomReader)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to generate bsr ed25519 key-pair %w: %w", op, err, ErrGenKey)
	}
	privBlob, err := bsrWrapper.Encrypt(ctx, priv)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to encrypt bsr ed25519 priv key %w: %w", op, err, ErrEncrypt)
	}
	marshaledPrivBlob, err := proto.Marshal(privBlob)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to marshal bsr ed25519 priv key %w: %w", op, err, ErrEncode)
	}
	retKeys.WrappedPrivKey = &wrapping.KeyInfo{
		KeyId:       sessionId,
		WrappedKey:  marshaledPrivBlob,
		KeyType:     wrapping.KeyType_Ed25519,
		KeyEncoding: wrapping.KeyEncoding_Bytes,
		KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
	}
	retKeys.PrivKey = &wrapping.KeyInfo{
		KeyId:       sessionId,
		Key:         priv,
		KeyType:     wrapping.KeyType_Ed25519,
		KeyEncoding: wrapping.KeyEncoding_Bytes,
		KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
	}
	retKeys.PubKey = &wrapping.KeyInfo{
		KeyId:       sessionId,
		Key:         pub,
		KeyType:     wrapping.KeyType_Ed25519,
		KeyEncoding: wrapping.KeyEncoding_Bytes,
		KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Verify},
	}
	privKeySigner, err := wrappingEd.NewSigner(ctx, wrappingEd.WithPrivKey(priv), wrapping.WithKeyId(sessionId))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	retKeys.PubKeySelfSignature, err = privKeySigner.Sign(ctx, pub)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrSign)
	}

	bsrKeyWrapper := aead.NewWrapper()
	if _, err := bsrKeyWrapper.SetConfig(ctx, wrapping.WithKeyId(sessionId)); err != nil {
		return nil, fmt.Errorf("%s: setting config on aead wrapper %w: %w", op, err, ErrUnknown)
	}
	if err := bsrKeyWrapper.SetAesGcmKeyBytes(bsrKey); err != nil {
		return nil, fmt.Errorf("%s: error setting key bytes on aead wrapper %w: %w", op, err, ErrUnknown)
	}
	marshaledSig, err := crypto.HmacSha256(ctx, pub, bsrKeyWrapper, crypto.WithMarshaledSigInfo())
	if err != nil {
		return nil, fmt.Errorf("%s: error signing pub key with bsr key %w: %w", op, err, ErrSign)
	}
	retKeys.PubKeyBsrSignature = &wrapping.SigInfo{}
	if err := proto.Unmarshal([]byte(marshaledSig), retKeys.PubKeyBsrSignature); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal sig info %w: %w", op, err, ErrEncode)
	}

	return retKeys, nil
}

// UnwrapBsrKey will unwrap the bsr key (k.WrappedBsrKey which is an AES-GCM)
// using the provide bsr kms. The k.BsrKey will be set to the unwrapped key
// key and returned in the form of an aead.Wrapper
//
// This is a concurrently safe operation.
func (k *Keys) UnwrapBsrKey(ctx context.Context, bsrWrapper wrapping.Wrapper, opt ...Option) (*aead.Wrapper, error) {
	const op = "kms.(BsrKeys).UnwrapBsrKey"
	if k == nil {
		return nil, fmt.Errorf("%s: nil bsr keys: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)

	// support just using an existing lock...
	if !opts.withAlreadyLocked {
		k.l.Lock()
		defer k.l.Unlock()
	}

	switch {
	case util.IsNil(bsrWrapper):
		return nil, fmt.Errorf("%s: missing bsr wrapper: %w", op, ErrInvalidParameter)
	case k.WrappedBsrKey == nil:
		return nil, fmt.Errorf("%s: missing wrapped bsr key: %w", op, ErrInvalidParameter)
	case k.WrappedBsrKey.KeyId == "":
		return nil, fmt.Errorf("%s: missing wrapped bsr key id: %w", op, ErrInvalidParameter)
	case k.WrappedBsrKey.WrappedKey == nil:
		return nil, fmt.Errorf("%s: missing wrapped bsr key bytes: %w", op, ErrInvalidParameter)
	case k.WrappedBsrKey.KeyType != wrapping.KeyType_Aes256:
		return nil, keyTypeError(ctx, op, wrapping.KeyType_Aes256, k.WrappedBsrKey.KeyType)
	case k.WrappedBsrKey.KeyEncoding != wrapping.KeyEncoding_Bytes:
		return nil, keyEncodingError(ctx, op, wrapping.KeyEncoding_Bytes, k.WrappedBsrKey.KeyEncoding)
	}

	var blob wrapping.BlobInfo

	if err := proto.Unmarshal(k.WrappedBsrKey.WrappedKey, &blob); err != nil {
		return nil, fmt.Errorf("%s: error unmarshaling wrapped bsr key %w: %w", op, err, ErrDecode)
	}

	keyBytes, err := bsrWrapper.Decrypt(ctx, &blob)
	if err != nil {
		return nil, fmt.Errorf("%s: error decrypting wrapped bsr key %w: %w", op, err, ErrDecrypt)
	}

	bsrKeyWrapper := aead.NewWrapper()
	if _, err := bsrKeyWrapper.SetConfig(ctx, wrapping.WithKeyId(k.WrappedBsrKey.KeyId)); err != nil {
		return nil, fmt.Errorf("%s: error setting config on aead wrapper %w: %w", op, err, ErrUnknown)
	}
	if err := bsrKeyWrapper.SetAesGcmKeyBytes(keyBytes); err != nil {
		return nil, fmt.Errorf("%s: error setting key bytes on aead wrapper %w: %w", op, err, ErrUnknown)
	}

	k.BsrKey = &wrapping.KeyInfo{
		Key:         keyBytes,
		KeyId:       k.WrappedBsrKey.KeyId,
		KeyType:     k.WrappedBsrKey.KeyType,
		KeyPurposes: k.WrappedBsrKey.KeyPurposes,
		KeyEncoding: wrapping.KeyEncoding_Bytes,
	}

	return bsrKeyWrapper, nil
}

// UnwrapPrivKey will unwrap the priv key (k.WrappedPrivKey which is an
// ed25519.PrivateKey) using the provide bsr kms.  The k.PrivKey will be set to
// the unwrapped key and returned in the form of an ed25519.PrivateKey
//
// This is a concurrently safe operation.
func (k *Keys) UnwrapPrivKey(ctx context.Context, bsrWrapper wrapping.Wrapper) (ed25519.PrivateKey, error) {
	const op = "kms.(BsrKeys).UnwrapPrivKey"
	if k == nil {
		return nil, fmt.Errorf("%s: nil bsr keys: %w", op, ErrInvalidParameter)
	}
	k.l.Lock()
	defer k.l.Unlock()

	switch {
	case util.IsNil(bsrWrapper):
		return nil, fmt.Errorf("%s: missing bsr wrapper: %w", op, ErrInvalidParameter)
	case k.WrappedPrivKey == nil:
		return nil, fmt.Errorf("%s: missing wrapped priv key: %w", op, ErrInvalidParameter)
	case k.WrappedPrivKey.KeyId == "":
		return nil, fmt.Errorf("%s: missing wrapped priv key id: %w", op, ErrInvalidParameter)
	case k.WrappedPrivKey.WrappedKey == nil:
		return nil, fmt.Errorf("%s: missing wrapped priv key bytes: %w", op, ErrInvalidParameter)
	case k.WrappedPrivKey.KeyType != wrapping.KeyType_Ed25519:
		return nil, keyTypeError(ctx, op, wrapping.KeyType_Ed25519, k.WrappedPrivKey.KeyType)
	case k.WrappedPrivKey.KeyEncoding != wrapping.KeyEncoding_Bytes:
		return nil, keyEncodingError(ctx, op, wrapping.KeyEncoding_Bytes, k.WrappedPrivKey.WrappedKeyEncoding)
	}
	var privKeyBlob wrapping.BlobInfo
	if err := proto.Unmarshal(k.WrappedPrivKey.WrappedKey, &privKeyBlob); err != nil {
		return nil, fmt.Errorf("%s: error unmarshaling wrapped priv key %w: %w", op, err, ErrDecode)
	}
	privKeyBytes, err := bsrWrapper.Decrypt(ctx, &privKeyBlob)
	if err != nil {
		return nil, fmt.Errorf("%s: error decrypting wrapped priv key %w: %w", op, err, ErrDecrypt)
	}
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: priv key must be %d bytes; got %d: %w", op, ed25519.PrivateKeySize, len(privKeyBytes), ErrInvalidParameter)
	}

	k.PrivKey = &wrapping.KeyInfo{
		Key:         privKeyBytes,
		KeyId:       k.WrappedPrivKey.KeyId,
		KeyType:     k.WrappedPrivKey.KeyType,
		KeyPurposes: k.WrappedPrivKey.KeyPurposes,
		KeyEncoding: wrapping.KeyEncoding_Bytes,
	}

	return ed25519.PrivateKey(privKeyBytes), nil
}

// VerifyPubKeyBsrSignature will verify the pub key signature created with the
// bsr key.  It will first try to use k.BsrKey, if that's not available it will
// attempt to unwrap k.WrappedBsrKey and use it for verification.  Supported
// options: WithBsrWrapper which is required if using k.WrappedBsrKey to verify
// the signature.
//
// This is a concurrently safe operation.
func (k *Keys) VerifyPubKeyBsrSignature(ctx context.Context, opt ...Option) (bool, error) {
	const op = "kms.(BsrKeys).VerifyPubKeyBsrSignature"
	switch {
	case k == nil:
		return false, fmt.Errorf("%s: nil bsr keys: %w", op, ErrInvalidParameter)
	case k.PubKey == nil:
		return false, fmt.Errorf("%s: missing pub key: %w", op, ErrInvalidParameter)
	case k.PubKeyBsrSignature == nil:
		return false, fmt.Errorf("%s: missing pub key signature: %w", op, ErrInvalidParameter)
	}
	ok, err := k.VerifySignatureWithBsrKey(ctx, k.PubKeyBsrSignature, ed25519.PublicKey(k.PubKey.Key), opt...)
	if err != nil {
		return ok, fmt.Errorf("%s: %w", op, err)
	}
	return ok, err
}

// VerifyPubKeySelfSignature will verify the self-signed pub key signature using
// k.PubKey. Note: this will tell you the signature is correct, but not if the
// public key is the right key; you want to use VerifyPubKeyBsrSignature(...)
// for that.
//
// This is a concurrently safe operation.
func (k *Keys) VerifyPubKeySelfSignature(ctx context.Context) (bool, error) {
	const op = "kms.(BsrKeys).VerifyPubKeySelfSignature"
	if k == nil {
		return false, fmt.Errorf("%s: bsr keys: %w", op, ErrInvalidParameter)
	}

	switch {
	case k.PubKey == nil:
		return false, fmt.Errorf("%s: missing pub key: %w", op, ErrInvalidParameter)
	case k.PubKey.Key == nil:
		return false, fmt.Errorf("%s: missing pub key bytes: %w", op, ErrInvalidParameter)
	case k.PubKey.KeyType != wrapping.KeyType_Ed25519:
		return false, keyTypeError(ctx, op, wrapping.KeyType_Ed25519, k.PubKey.KeyType)
	case k.PubKey.KeyEncoding != wrapping.KeyEncoding_Bytes:
		return false, keyEncodingError(ctx, op, wrapping.KeyEncoding_Bytes, k.PubKey.KeyEncoding)
	case len(k.PubKey.Key) != ed25519.PublicKeySize:
		return false, fmt.Errorf("%s: expected public key with %d bytes and got %d: %w", op, ed25519.PublicKeySize, len(k.PubKey.Key), ErrInvalidParameter)
	case k.PubKeySelfSignature == nil:
		return false, fmt.Errorf("%s: missing pub key self signature: %w", op, ErrInvalidParameter)
	case k.PubKeySelfSignature.KeyInfo.KeyId != k.PubKey.KeyId:
		return false, fmt.Errorf("%s: pub self signature key id %q doesn't match verifying pub key id %q: %w", op, k.PubKeySelfSignature.KeyInfo.KeyId, k.PubKey.KeyId, ErrInvalidParameter)
	}

	return k.VerifySignatureWithPubKey(ctx, k.PubKeySelfSignature, k.PubKey.Key)
}

// SignWithPrivKey will sign the msg with the BsrKeys.PrivKey (aka the BSR's
// ed25519.PrivateKey). Typical usage is to sign the BSR's checksums file.
//
// This is a concurrently safe operation.
func (k *Keys) SignWithPrivKey(ctx context.Context, msg []byte) (*wrapping.SigInfo, error) {
	const op = "kms.(BsrKeys).SignWithPrivKey"
	if k == nil {
		return nil, fmt.Errorf("%s: nil bsr keys: %w", op, ErrInvalidParameter)
	}
	k.l.RLock()
	defer k.l.RUnlock()

	switch {
	case msg == nil:
		return nil, fmt.Errorf("%s: missing msg: %w", op, ErrInvalidParameter)
	case k.PrivKey == nil:
		return nil, fmt.Errorf("%s: missing priv key: %w", op, ErrInvalidParameter)
	case k.PrivKey.KeyId == "":
		return nil, fmt.Errorf("%s: missing priv key id: %w", op, ErrInvalidParameter)
	case k.PrivKey.Key == nil:
		return nil, fmt.Errorf("%s: missing priv key bytes: %w", op, ErrInvalidParameter)
	case k.PrivKey.KeyType != wrapping.KeyType_Ed25519:
		return nil, keyTypeError(ctx, op, wrapping.KeyType_Ed25519, k.PrivKey.KeyType)
	case k.PrivKey.KeyEncoding != wrapping.KeyEncoding_Bytes:
		return nil, keyEncodingError(ctx, op, wrapping.KeyEncoding_Bytes, k.PrivKey.KeyEncoding)
	case len(k.PrivKey.Key) != ed25519.PrivateKeySize:
		return nil, fmt.Errorf("%s: expected priv key with %d bytes and got %d: %w", op, ed25519.PrivateKeySize, len(k.PrivKey.Key), ErrInvalidParameter)
	}

	s, err := wrappingEd.NewSigner(ctx,
		wrappingEd.WithPrivKey(k.PrivKey.Key),
		wrapping.WithKeyId(k.PrivKey.KeyId),
		wrapping.WithKeyEncoding(k.PrivKey.KeyEncoding),
		wrapping.WithKeyPurposes(k.PrivKey.KeyPurposes...),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create priv key signer: %w", op, err)
	}
	si, err := s.Sign(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrSign)
	}
	return si, nil
}

// VerifySignatureWithPubKey will verify a signature using the k.PubKey.
//
// This is a concurrently safe operation.
func (k *Keys) VerifySignatureWithPubKey(ctx context.Context, sig *wrapping.SigInfo, msg []byte) (bool, error) {
	const op = "kms.(BsrKeys).VerifySignatureWithPubKey"
	if k == nil {
		return false, fmt.Errorf("%s: bsr keys: %w", op, ErrInvalidParameter)
	}
	k.l.RLock()
	defer k.l.RUnlock()

	switch {
	case k.PubKey == nil:
		return false, fmt.Errorf("%s: missing pub key: %w", op, ErrInvalidParameter)
	case k.PubKey.Key == nil:
		return false, fmt.Errorf("%s: missing pub key bytes: %w", op, ErrInvalidParameter)
	case k.PubKey.KeyType != wrapping.KeyType_Ed25519:
		return false, keyTypeError(ctx, op, wrapping.KeyType_Ed25519, k.PubKey.KeyType)
	case k.PubKey.KeyEncoding != wrapping.KeyEncoding_Bytes:
		return false, keyEncodingError(ctx, op, wrapping.KeyEncoding_Bytes, k.PubKey.KeyEncoding)
	case len(k.PubKey.Key) != ed25519.PublicKeySize:
		return false, fmt.Errorf("%s: expected public key with %d bytes and got %d: %w", op, ed25519.PublicKeySize, len(k.PubKey.Key), ErrInvalidParameter)
	case sig == nil:
		return false, fmt.Errorf("%s: missing signature info: %w", op, ErrInvalidParameter)
	case msg == nil:
		return false, fmt.Errorf("%s: missing message: %w", op, ErrInvalidParameter)
	}

	verifier, err := wrappingEd.NewVerifier(ctx, wrappingEd.WithPubKey(k.PubKey.Key))
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	ok, err := verifier.Verify(ctx, msg, sig)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return ok, nil
}

func (k *Keys) VerifySignatureWithBsrKey(ctx context.Context, sig *wrapping.SigInfo, msg []byte, opt ...Option) (bool, error) {
	const op = "kms.(BsrKeys).VerifySignatureWithBsrKey"
	if k == nil {
		return false, fmt.Errorf("%s: nil bsr keys: %w", op, ErrInvalidParameter)
	}
	// needs a write lock since it may need to UnwrapBsrKey(...)
	k.l.Lock()
	defer k.l.Unlock()

	switch {
	case k.BsrKey == nil && k.WrappedBsrKey == nil:
		return false, fmt.Errorf("%s: missing bsr key and wrapped bsr key: %w", op, ErrInvalidParameter)
	case k.BsrKey != nil && k.BsrKey.Key == nil:
		return false, fmt.Errorf("%s: missing bsr key bytes: %w", op, ErrInvalidParameter)
	case k.WrappedBsrKey != nil && k.WrappedBsrKey.WrappedKey == nil:
		return false, fmt.Errorf("%s: missing wrapped bsr key bytes: %w", op, ErrInvalidParameter)
	case len(msg) == 0:
		return false, fmt.Errorf("%s: missing msg: %w", op, ErrInvalidParameter)
	case sig == nil:
		return false, fmt.Errorf("%s: missing signature: %w", op, ErrInvalidParameter)
	case sig.KeyInfo == nil:
		return false, fmt.Errorf("%s: missing signature key info: %w", op, ErrInvalidParameter)
	case len(sig.Signature) == 0:
		return false, fmt.Errorf("%s: signature is empty: %w", op, ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	var bsrKeyWrapper *aead.Wrapper
	switch {
	case k.BsrKey != nil:
		switch {
		case k.BsrKey.KeyType != wrapping.KeyType_Aes256:
			return false, keyTypeError(ctx, op, wrapping.KeyType_Aes256, k.BsrKey.KeyType)
		case k.BsrKey.KeyEncoding != wrapping.KeyEncoding_Bytes:
			return false, keyEncodingError(ctx, op, wrapping.KeyEncoding_Bytes, k.BsrKey.KeyEncoding)
		}
		bsrKeyWrapper = aead.NewWrapper()
		if _, err := bsrKeyWrapper.SetConfig(ctx, wrapping.WithKeyId(k.BsrKey.KeyId)); err != nil {
			return false, fmt.Errorf("%s: error setting config on bsr key wrapper %w: %w", op, err, ErrUnknown)
		}
		if err := bsrKeyWrapper.SetAesGcmKeyBytes(k.BsrKey.Key); err != nil {
			return false, fmt.Errorf("%s: error setting key bytes on bsr key wrapper %w: %w", op, err, ErrUnknown)
		}
	case k.WrappedBsrKey != nil:
		switch {
		case util.IsNil(opts.withBsrWrapper):
			return false, fmt.Errorf("%s: missing bsr wrapper: %w", op, ErrInvalidParameter)
		case k.WrappedBsrKey.KeyType != wrapping.KeyType_Aes256:
			return false, keyTypeError(ctx, op, wrapping.KeyType_Aes256, k.WrappedBsrKey.KeyType)
		case k.WrappedBsrKey.KeyEncoding != wrapping.KeyEncoding_Bytes:
			return false, keyEncodingError(ctx, op, wrapping.KeyEncoding_Bytes, k.WrappedBsrKey.KeyEncoding)
		}
		var err error
		if bsrKeyWrapper, err = k.UnwrapBsrKey(ctx, opts.withBsrWrapper, withAlreadyLocked(true)); err != nil {
			return false, fmt.Errorf("%s: error unwrapping bsr key: %w", op, err)
		}
	default:
		return false, fmt.Errorf("%s: missing bsr key and wrapped bsr key: %w", op, ErrInvalidParameter)
	}
	marshaledSigInfo, err := crypto.HmacSha256(ctx, msg, bsrKeyWrapper, crypto.WithMarshaledSigInfo())
	if err != nil {
		return false, fmt.Errorf("%s: error signing msg %w: %w", op, err, ErrSign)
	}
	var sigInfo wrapping.SigInfo
	if err = proto.Unmarshal([]byte(marshaledSigInfo), &sigInfo); err != nil {
		return false, fmt.Errorf("%s: error unmarshaling sig info %w: %w", op, err, ErrDecode)
	}
	bsrKeyId, err := bsrKeyWrapper.KeyId(ctx)
	if err != nil {
		return false, fmt.Errorf("%s: error getting bsr key id %w: %w", op, err, ErrUnknown)
	}
	if sig.KeyInfo.KeyId != bsrKeyId {
		return false, fmt.Errorf("%s: signature key id %q doesn't match verifying key id %q: %w", op, k.PubKeyBsrSignature.KeyInfo.KeyId, bsrKeyId, ErrInvalidParameter)
	}
	if subtle.ConstantTimeCompare(sig.Signature, sigInfo.Signature) == 1 {
		return true, nil
	}
	return false, nil
}

func keyTypeError(ctx context.Context, fromOp string, want wrapping.KeyType, got wrapping.KeyType) error {
	return fmt.Errorf(
		"%s: unexpected key type %q; expected %q: %w",
		fromOp,
		wrapping.KeyType_name[int32(got)],
		wrapping.KeyType_name[int32(want)],
		ErrInvalidParameter,
	)
}

func keyEncodingError(ctx context.Context, fromOp string, want wrapping.KeyEncoding, got wrapping.KeyEncoding) error {
	return fmt.Errorf(
		"%s: unexpected key encoding %q; expected %q: %w",
		fromOp,
		wrapping.KeyEncoding_name[int32(got)],
		wrapping.KeyEncoding_name[int32(want)],
		ErrInvalidParameter,
	)
}
