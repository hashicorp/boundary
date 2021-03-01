package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	wrapping "github.com/hashicorp/go-kms-wrapping"

	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

const (
	AttemptExpiration     = 2 * 60 * time.Second
	FinalRedirectEndpoint = "/authentication-complete" // TODO jimlambrt 2/2021 get redirect from FE before PR
	CallbackEndpoint      = "/callback"                // TODO jimlambrt 2/2021 get endpoint from Todd before PR
)

type (
	// OidcRepoFactory creates a new oidc repo
	OidcRepoFactory func() (*Repository, error)

	// IamRepoFactory creates a new iam repo
	IamRepoFactory func() (*iam.Repository, error)

	// AuthTokenRepFactory creates a new auth token repo
	AuthTokenRepFactory func() (*authtoken.Repository, error)
)

type validator interface {
	Validate() error
}

// encryptMessage will encrypt the message.  The encrypted message will be wrapped in a
// request.Wrapper and then encoded into the returned string. This function
// supports encrypting: request.State and request.Token messages
func encryptMessage(ctx context.Context, wrapper wrapping.Wrapper, am *AuthMethod, m proto.Message) (encodedEncryptedState string, e error) {
	const op = "oidc.encryptMessage"
	if wrapper == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	if am == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if m == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing message to encrypt")
	}
	switch v := m.(type) {
	case *request.State, *request.Token:
	default:
		return "", errors.New(errors.InvalidParameter, op, fmt.Sprintf("unsupported message type %v for encryption", v))
	}

	v, ok := m.(validator)
	if ok {
		if err := v.Validate(); err != nil {
			return "", errors.Wrap(err, op)
		}
	}
	marshaled, err := proto.Marshal(m)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("unable to marshal message"), errors.WithCode(errors.Encode))
	}
	blobInfo, err := wrapper.Encrypt(ctx, marshaled, nil)
	if err != nil {
		return "", errors.New(errors.Encrypt, op, "unable to encrypt message", errors.WithWrap(err))
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("unable to marshal blob"), errors.WithCode(errors.Encode))
	}
	wrapped := &request.Wrapper{
		AuthMethodId: am.PublicId,
		ScopeId:      am.ScopeId,
		WrapperKeyId: wrapper.KeyID(),
		Ct:           marshaledBlob,
	}
	if err := wrapped.Validate(); err != nil {
		return "", errors.Wrap(err, op)
	}
	marshaledEncryptedSt, err := proto.Marshal(wrapped)
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to marshal encrypted message", errors.WithWrap(err))
	}

	return base58.FastBase58Encoding(marshaledEncryptedSt), nil
}

// decryptMessage will decrypt messages that were previously encrypted with oidc.encryptMessage(...)
// The messageBytes returned can be marshaled via proto.Marshal into the appropriate message.
func decryptMessage(ctx context.Context, wrapper wrapping.Wrapper, encodedEncryptedMessage string) (scopeId string, authMethodId string, messageBytes []byte, e error) {
	const op = "oidc.decryptMessage"
	if wrapper == nil {
		return "", "", nil, errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	if encodedEncryptedMessage == "" {
		return "", "", nil, errors.New(errors.InvalidParameter, op, "missing encoded/encrypted message")
	}
	decoded, err := base58.FastBase58Decoding(encodedEncryptedMessage)
	if err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to decode message", errors.WithWrap(err))
	}
	var wrapped request.Wrapper
	if err := proto.Unmarshal(decoded, &wrapped); err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to marshal encoded/encrypted message", errors.WithWrap(err))
	}

	var blobInfo wrapping.EncryptedBlobInfo
	if err := proto.Unmarshal(wrapped.Ct, &blobInfo); err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to marshal blob info", errors.WithWrap(err))
	}

	decryptedMsg, err := wrapper.Decrypt(ctx, &blobInfo, nil)
	if err != nil {
		return "", "", nil, errors.New(errors.Encrypt, op, "unable to decrypt message", errors.WithWrap(err))
	}

	return wrapped.ScopeId, wrapped.AuthMethodId, decryptedMsg, nil
}
