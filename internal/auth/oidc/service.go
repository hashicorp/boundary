// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aead "github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

const (
	// AttemptExpiration defines the TTL for an authentication attempt
	AttemptExpiration = 5 * 60 * time.Second

	// FinalRedirectEndpoint is the endpoint that the oidc callback redirect
	// client to after the callback is complete.
	FinalRedirectEndpoint = "%s/authentication-complete"

	// AuthenticationErrorsEndpoint is the endpoint that will returned as the final redirect
	// from the callback when there are auth errors
	AuthenticationErrorsEndpoint = "%s/authentication-error"

	// CallbackEndpoint is the endpoint for the oidc callback which will be
	// included in the auth URL returned when an authen attempted is kicked off.
	CallbackEndpoint = "%s/v1/auth-methods/oidc:authenticate:callback"
)

type (
	// OidcRepoFactory is used by "service functions" to create a new oidc repo
	OidcRepoFactory func() (*Repository, error)

	// IamRepoFactory is used by "service functions" to create a new iam repo
	IamRepoFactory func() (*iam.Repository, error)

	// AuthTokenRepoFactory is used by "service functions" to create a new auth token repo
	AuthTokenRepoFactory func() (*authtoken.Repository, error)
)

// validator defines an optional interface that proto messages can implement
// which will allow encryptMessage to validate them before encryption.
type validator interface {
	Validate() error
}

// encryptMessage will encrypt the message.  The encrypted message will be wrapped in a
// request.Wrapper and then encoded into the returned string. This function
// supports encrypting: request.State and request.Token messages.  proto Messages should
// implement the validator interface, so they can be validated before encryption.
func encryptMessage(ctx context.Context, wrapper wrapping.Wrapper, am *AuthMethod, m proto.Message) (encodedEncryptedState string, e error) {
	const op = "oidc.encryptMessage"
	if wrapper == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing wrapper")
	}
	keyId, err := wrapper.KeyId(ctx)
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("error fetching wrapper key id"))
	}
	if keyId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing wrapper key id")
	}
	if am == nil || am.AuthMethod == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	}
	if am.ScopeId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing auth method scope id")
	}
	if am.PublicId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing auth method public id")
	}
	if m == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing message to encrypt")
	}
	switch v := m.(type) {
	case *request.State, *request.Token:
	default:
		return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported message type %v for encryption", v))
	}

	v, ok := m.(validator)
	if ok {
		if err := v.Validate(); err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
	}
	marshaled, err := proto.Marshal(m)
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal message"), errors.WithCode(errors.Encode))
	}
	blobInfo, err := wrapper.Encrypt(ctx, marshaled, wrapping.WithAad([]byte(fmt.Sprintf("%s%s", am.PublicId, am.ScopeId))))
	if err != nil {
		return "", errors.New(ctx, errors.Encrypt, op, "unable to encrypt message", errors.WithWrap(err))
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal blob"), errors.WithCode(errors.Encode))
	}
	wrapped := &request.Wrapper{
		AuthMethodId: am.PublicId,
		ScopeId:      am.ScopeId,
		WrapperKeyId: keyId,
		Ct:           marshaledBlob,
	}
	if err := wrapped.Validate(ctx); err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	marshaledEncryptedSt, err := proto.Marshal(wrapped)
	if err != nil {
		return "", errors.New(ctx, errors.Unknown, op, "unable to marshal encrypted message", errors.WithWrap(err))
	}

	return base58.FastBase58Encoding(marshaledEncryptedSt), nil
}

// decryptMessage will decrypt messages that were previously encrypted with oidc.encryptMessage(...)
// The returned messageBytes can be marshaled via proto.Marshal into the appropriate message.
func decryptMessage(ctx context.Context, wrappingWrapper wrapping.Wrapper, wrappedRequest *request.Wrapper) (messageBytes []byte, e error) {
	const op = "oidc.decryptMessage"
	if wrappedRequest == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing wrapped request")
	}
	if wrappingWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing wrapping wrapper")
	}
	var blobInfo wrapping.BlobInfo
	if err := proto.Unmarshal(wrappedRequest.Ct, &blobInfo); err != nil {
		return nil, errors.New(ctx, errors.Unknown, op, "unable to marshal blob info", errors.WithWrap(err))
	}

	decryptedMsg, err := wrappingWrapper.Decrypt(ctx, &blobInfo, wrapping.WithAad([]byte(fmt.Sprintf("%s%s", wrappedRequest.AuthMethodId, wrappedRequest.ScopeId))))
	if err != nil {
		return nil, errors.New(ctx, errors.Decrypt, op, "unable to decrypt message", errors.WithWrap(err))
	}
	return decryptedMsg, nil
}

// UnwrapMessage does just that, it unwraps the encoded request.Wrapper proto message
func UnwrapMessage(ctx context.Context, encodedWrappedMsg string) (*request.Wrapper, error) {
	const op = ""
	decoded, err := base58.FastBase58Decoding(encodedWrappedMsg)
	if err != nil {
		return nil, errors.New(ctx, errors.Unknown, op, "unable to decode message", errors.WithWrap(err))
	}
	var wrapper request.Wrapper
	if err := proto.Unmarshal(decoded, &wrapper); err != nil {
		return nil, errors.New(ctx, errors.Unknown, op, "unable to marshal encoded/encrypted message", errors.WithWrap(err))
	}
	return &wrapper, nil
}

// requestWrappingWrapper finds the wrapping wrapper to use when encrypting/decrypting
// both a Request.State and Request.Token.
//
// It first checks the cache of derived wrappers. If it's not found in the cache, it
// generates a key based on the scope's oidc DEK, using the scopeId and authMethod
// as salt and info for derivation, creates a wrapper for the new key, adds that wrapper
// to the cache and the returns the wrapper for the new key.
//
// It supports the WithKeyId(...) option which allows you to specify which oidc DEK
// to use vs the default of just using the latest version of the DEK.
func requestWrappingWrapper(ctx context.Context, k *kms.Kms, scopeId, authMethodId string, opt ...Option) (wrapping.Wrapper, error) {
	const op = "oidc.(Repository).oidcWrapper"
	if k == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if authMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	opts := getOpts(opt...)
	// get a specific oidcWrapper using the WithKeyId(...) option
	oidcWrapper, err := k.GetWrapper(ctx, scopeId, kms.KeyPurposeOidc, kms.WithKeyId(opts.withKeyId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oidc wrapper"))
	}

	// What derived key are we looking for?
	keyId, err := oidcWrapper.KeyId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oidc wrapper key id"))
	}
	keyId = derivedKeyId(derivedKeyPurposeState, keyId, authMethodId)
	derivedWrapper, ok := k.GetDerivedPurposeCache().Load(keyId)
	if ok {
		return derivedWrapper.(*aead.Wrapper), nil
	}

	// okay, I guess we need to derive a new key for this combo of oidcWrapper and authMethod
	reader, err := crypto.NewDerivedReader(ctx, oidcWrapper, 32, []byte(authMethodId), []byte(scopeId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	privKey, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, errors.New(ctx, errors.Encrypt, op, "unable to generate key", errors.WithWrap(err))
	}
	wrapper := aead.NewWrapper()
	if _, err := wrapper.SetConfig(ctx, wrapping.WithKeyId(keyId)); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error setting config on aead wrapper in auth method %s", authMethodId)))
	}
	if err := wrapper.SetAesGcmKeyBytes(privKey); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error setting key bytes on aead wrapper in auth method %s", authMethodId)))
	}
	// store the derived key in our cache
	k.GetDerivedPurposeCache().Store(keyId, wrapper)

	return wrapper, nil
}

// derivedKeyId returns a key that represents the derived key
func derivedKeyId(purpose derivedKeyPurpose, wrapperKeyId, authMethodId string) string {
	return fmt.Sprintf("%s.%s.%s", purpose.String(), wrapperKeyId, authMethodId)
}

// derivedKeyPurpose represents the purpose of the derived key.
//
// In the future, this could be moved to the kms package
// and exported for others to use.
type derivedKeyPurpose uint

const (
	derivedKeyPurposeUnknown = iota
	derivedKeyPurposeState
)

// String returns a representative string for the key's purpose
func (k derivedKeyPurpose) String() string {
	switch k {
	case derivedKeyPurposeState:
		return "oidc_state"
	default:
		return "oidc_unknown"
	}
}
