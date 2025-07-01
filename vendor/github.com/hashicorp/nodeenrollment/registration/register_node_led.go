// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package registration

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// validateFetchRequestCommon is common logic between FetchNodeCredentials and
// AuthorizeNode to validate the incoming request.
//
// NOTE: Users of the function should check the error to see if it is
// nodeenrollment.ErrNotFound and customize logic appropriately. It is possible
// for this function to return request info and also ErrNotFound to enable this.
//
// Supported options: WithStorageWrapper (passed through to
// LoadNodeInformation), WithNotBeforeClockSkew/WithNotAfterClockSkew, WithState
// (passed through to authorizeNodeCommon.
func validateFetchRequestCommon(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.FetchNodeCredentialsRequest,
	opt ...nodeenrollment.Option,
) (*types.FetchNodeCredentialsInfo, error) {
	const op = "nodeenrollment.registration.validateFetchRequest"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request", op)
	case len(req.Bundle) == 0:
		return nil, fmt.Errorf("(%s) empty bundle", op)
	case len(req.BundleSignature) == 0:
		return nil, fmt.Errorf("(%s) empty bundle signature", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	reqInfo := new(types.FetchNodeCredentialsInfo)
	if err := proto.Unmarshal(req.Bundle, reqInfo); err != nil {
		return nil, fmt.Errorf("(%s) cannot unmarshal request info: %w", op, err)
	}

	now := time.Now()
	switch {
	case len(reqInfo.CertificatePublicKeyPkix) == 0:
		return nil, fmt.Errorf("(%s) empty node certificate public key", op)
	case reqInfo.CertificatePublicKeyType != types.KEYTYPE_ED25519:
		return nil, fmt.Errorf("(%s) unsupported node certificate public key type %v", op, reqInfo.CertificatePublicKeyType.String())
	case len(reqInfo.Nonce) == 0:
		return nil, fmt.Errorf("(%s) empty nonce", op)
	case len(reqInfo.EncryptionPublicKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) empty node encryption public key", op)
	case reqInfo.EncryptionPublicKeyType != types.KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) unsupported node encryption public key type %v", op, reqInfo.EncryptionPublicKeyType.String())
	case reqInfo.NotBefore.AsTime().Add(opts.WithNotBeforeClockSkew).After(now):
		return nil, fmt.Errorf("(%s) validity period is after current time", op)
	case reqInfo.NotAfter.AsTime().Add(opts.WithNotAfterClockSkew).Before(now):
		return nil, fmt.Errorf("(%s) validity period is before current time", op)
	}

	pubKeyRaw, err := x509.ParsePKIXPublicKey(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing public key: %w", op, err)
	}
	pubKey, ok := pubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("(%s) error considering public key as ed25519: %w", op, err)
	}
	if !ed25519.Verify(pubKey, req.Bundle, req.BundleSignature) {
		return nil, fmt.Errorf("(%s) request bytes signature verification failed", op)
	}

	return reqInfo, nil
}

// FetchNodeCredentials fetches node credentials based on the submitted
// information.
//
// Supported options: WithRandomReader, WithRegistrationWrapper,
// WithStorageWrapper (passed through to LoadNodeInformation,
// NodeInformation.Store, and LoadRootCertificates),
// WithNotBeforeClockSkew/WithNotAfterClockSkew/WithState (passed through to
// validateFetchRequest), WithLogger
//
// Note: If the request nonce is a server-led activation token and it contains
// state, this will overwrite any state passed in via options to this function;
// either transfer state via the activation token, or when calling this
// function.
func FetchNodeCredentials(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.FetchNodeCredentialsRequest,
	opt ...nodeenrollment.Option,
) (*types.FetchNodeCredentialsResponse, error) {
	const op = "nodeenrollment.registration.FetchNodeCredentials"

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var nodeInfo *types.NodeInformation
	reqInfo, err := validateFetchRequestCommon(ctx, storage, req, opt...)
	switch {
	case err != nil:
		err := fmt.Errorf("(%s) error during fetch request validation: %w", op, err)
		return nil, err

	case len(reqInfo.WrappedRegistrationInfo) > 0 || len(req.RewrappedWrappingRegistrationFlowInfo) > 0:
		var registrationInfo *types.WrappingRegistrationFlowInfo
		if len(req.RewrappedWrappingRegistrationFlowInfo) > 0 {
			encryptingNodeInfo, err := types.LoadNodeInformation(ctx, storage, req.RewrappingKeyId, opt...)
			if err != nil {
				err := fmt.Errorf("error looking up node information for rewrapping key id: %w", err)
				opts.WithLogger.Error(err.Error(), "op", op)
				return nil, fmt.Errorf("(%s) %s", op, err.Error())
			}
			registrationInfo = new(types.WrappingRegistrationFlowInfo)
			if err := nodeenrollment.DecryptMessage(ctx, req.RewrappedWrappingRegistrationFlowInfo, encryptingNodeInfo, registrationInfo); err != nil {
				err := fmt.Errorf("error decrypting rewrapped registration info: %w", err)
				opts.WithLogger.Error(err.Error(), "op", op)
				return nil, fmt.Errorf("(%s) %s", op, err.Error())
			}
		} else {
			registrationInfo, err = DecryptWrappedRegistrationInfo(ctx, reqInfo, opt...)
			if err != nil {
				err := fmt.Errorf("error decrypting wrapped registration info: %w", err)
				opts.WithLogger.Error(err.Error(), "op", op)
				return nil, fmt.Errorf("(%s) %s", op, err.Error())
			}
		}
		if registrationInfo == nil {
			err := errors.New("registration info nil after decryption")
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}

		// Regardless of how we got the decrypted data, perform validation here
		// since here is where we validated the signature on the bundle and the
		// overall validity of the bundle
		if subtle.ConstantTimeCompare(registrationInfo.Nonce, reqInfo.Nonce) != 1 {
			err := errors.New("mismatched nonce in unwrapped registration info")
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}
		if subtle.ConstantTimeCompare(registrationInfo.CertificatePublicKeyPkix, reqInfo.CertificatePublicKeyPkix) != 1 {
			err := errors.New("mismatched public key in unwrapped registration info")
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}
		// Cache the decrypted registration information so that it's usable when
		// authorizing the node
		reqInfo.WrappingRegistrationFlowInfo = registrationInfo

		nodeInfo, err = authorizeNodeCommon(ctx, storage, reqInfo, opt...)
		if err != nil {
			err := fmt.Errorf("error authorizing node after validating wrapping-flow registration: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}

	case len(reqInfo.Nonce) == nodeenrollment.NonceSize:
		// This is our normal fetch case with node-led activation
		keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
		if err != nil {
			return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
		}

		nodeInfo, err = types.LoadNodeInformation(ctx, storage, keyId, opt...)
		switch {
		case err != nil && !errors.Is(err, nodeenrollment.ErrNotFound):
			return nil, fmt.Errorf("(%s) error looking up node information from storage: %w", op, err)
		case err != nil, nodeInfo == nil:
			// Unauthorized, so return empty. We cannot return nil because this
			// will
			// cause a marshal error if this function is via RPC since gRPC does not
			// allow nil responses.
			return new(types.FetchNodeCredentialsResponse), nil
		}

	case len(reqInfo.Nonce) > 0:
		// In this case where we have a non-standard nonce size it is containing
		// a server-led activation token, which is a proto marshal and may vary
		// in size, so expect that
		tokenNonce := new(types.ServerLedActivationTokenNonce)
		if err := proto.Unmarshal(reqInfo.Nonce, tokenNonce); err != nil {
			if strings.Contains(err.Error(), "cannot parse invalid wire-format data") {
				return nil, fmt.Errorf("(%s) invalid registration nonce: %w", op, err)
			}
			return nil, fmt.Errorf("(%s) error unmarshaling server-led activation token: %w", op, err)
		}
		switch {
		case len(tokenNonce.Nonce) == 0:
			return nil, fmt.Errorf("(%s) nil server-led activation token nonce", op)
		case len(tokenNonce.HmacKeyBytes) == 0:
			return nil, fmt.Errorf("(%s) nil server-led activation token hmac key bytes", op)
		}
		nodeInfo, err = validateServerLedActivationToken(ctx, storage, reqInfo, tokenNonce, opt...)
		if err != nil {
			err := fmt.Errorf("error validating server-led activation token: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}

	default:
		// No error but we don't know what to do in this condition
		return nil, fmt.Errorf("(%s) bad registration information during fetch", op)
	}

	// Run some validations
	if subtle.ConstantTimeCompare(nodeInfo.RegistrationNonce, reqInfo.Nonce) != 1 {
		return nil, fmt.Errorf("(%s) mismatched nonces between authorization and incoming fetch request", op)
	}

	if subtle.ConstantTimeCompare(nodeInfo.CertificatePublicKeyPkix, reqInfo.CertificatePublicKeyPkix) != 1 {
		return nil, fmt.Errorf("(%s) mismatched certificate public keys between authorization and incoming fetch request", op)
	}

	if subtle.ConstantTimeCompare(nodeInfo.EncryptionPublicKeyBytes, reqInfo.EncryptionPublicKeyBytes) != 1 {
		return nil, fmt.Errorf("(%s) mismatched encryption public keys between authorization and incoming fetch request", op)
	}

	serverEncryptionPrivateKey, err := ecdh.X25519().NewPrivateKey(nodeInfo.ServerEncryptionPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("(%s) error reading server private encryption key: %w", op, err)
	}
	serverEncryptionPublicKey := serverEncryptionPrivateKey.PublicKey()

	nodeCreds := &types.NodeCredentials{
		ServerEncryptionPublicKeyBytes: serverEncryptionPublicKey.Bytes(),
		ServerEncryptionPublicKeyType:  nodeInfo.ServerEncryptionPrivateKeyType,
		RegistrationNonce:              nodeInfo.RegistrationNonce,
		CertificateBundles:             nodeInfo.CertificateBundles,
	}

	encryptedBytes, err := nodeenrollment.EncryptMessage(
		ctx,
		nodeCreds,
		nodeInfo,
		opt...,
	)
	if err != nil {
		return nil, fmt.Errorf("(%s) error encrypting message: %w", op, err)
	}

	rootCerts, err := types.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error fetching current root certificates: %w", op, err)
	}

	_, signer, err := rootCerts.Current.SigningParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("(%s) error getting signing params: %w", op, err)
	}

	sigBytes, err := signer.Sign(opts.WithRandomReader, encryptedBytes, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("(%s) error signing request data message: %w", op, err)
	}

	return &types.FetchNodeCredentialsResponse{
		EncryptedNodeCredentials:          encryptedBytes,
		EncryptedNodeCredentialsSignature: sigBytes,
		ServerEncryptionPublicKeyBytes:    serverEncryptionPublicKey.Bytes(),
		ServerEncryptionPublicKeyType:     nodeInfo.ServerEncryptionPrivateKeyType,
	}, nil
}

// DecryptWrappedRegistrationInfo is shared functionality for decrypting wrapped
// registration information that can be used both within registration and during
// multi-hop contexts
func DecryptWrappedRegistrationInfo(ctx context.Context, reqInfo *types.FetchNodeCredentialsInfo, opt ...nodeenrollment.Option) (*types.WrappingRegistrationFlowInfo, error) {
	const op = "nodeenrollment.registration.DecryptWrappedRegistrationInfo"
	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		err := fmt.Errorf("error parsing options: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	if nodeenrollment.IsNil(reqInfo) {
		err := errors.New("fetch request is nil")
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	if nodeenrollment.IsNil(opts.WithRegistrationWrapper) {
		err := fmt.Errorf("wrapped registration information in fetch request but no registration wrapper provided: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	blobInfo := new(wrapping.BlobInfo)
	if err := proto.Unmarshal(reqInfo.WrappedRegistrationInfo, blobInfo); err != nil {
		err := fmt.Errorf("error unmarshaling encrypted wrapped registration info: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	registrationInfoBytes, err := opts.WithRegistrationWrapper.Decrypt(ctx, blobInfo)
	if err != nil {
		err := fmt.Errorf("error decrypting encrypted wrapped registration info: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	registrationInfo := new(types.WrappingRegistrationFlowInfo)
	if err := proto.Unmarshal(registrationInfoBytes, registrationInfo); err != nil {
		err := fmt.Errorf("error unmarshaling decrypted wrapped registration info: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	return registrationInfo, nil
}
