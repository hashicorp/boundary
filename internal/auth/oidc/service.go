package oidc

import (
	"context"
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

func encryptState(ctx context.Context, wrapper wrapping.Wrapper, am *AuthMethod, reqState *request.State) (encodedEncryptedState string, e error) {
	const op = "oidc.encryptState"
	if wrapper == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	if am == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if reqState == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing request state")
	}
	if err := reqState.Validate(); err != nil {
		return "", errors.Wrap(err, op)
	}
	marshaled, err := proto.Marshal(reqState)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("marshaling encrypted token"), errors.WithCode(errors.Encode))
	}
	blobInfo, err := wrapper.Encrypt(ctx, marshaled, nil)
	if err != nil {
		return "", errors.New(errors.Encrypt, op, "unable to encrypt request state", errors.WithWrap(err))
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("marshaling encrypted token"), errors.WithCode(errors.Encode))
	}
	encryptedSt := &request.EncryptedState{
		AuthMethodId: am.PublicId,
		ScopeId:      am.ScopeId,
		WrapperKeyId: wrapper.KeyID(),
		Ct:           marshaledBlob,
	}
	marshaledEncryptedSt, err := proto.Marshal(encryptedSt)
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to marshal encrypted state", errors.WithWrap(err))
	}

	return base58.FastBase58Encoding(marshaledEncryptedSt), nil
}

func decryptState(ctx context.Context, wrapper wrapping.Wrapper, encodedEncryptedState string) (string, string, *request.State, error) {
	const op = "oidc.decryptState"
	if wrapper == nil {
		return "", "", nil, errors.New(errors.InvalidParameter, op, "missing wrapper")
	}
	if encodedEncryptedState == "" {
		return "", "", nil, errors.New(errors.InvalidParameter, op, "missing encoded/encrypted state")
	}
	decoded, err := base58.FastBase58Decoding(encodedEncryptedState)
	if err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to decode state", errors.WithWrap(err))
	}
	var encryptedSt request.EncryptedState
	if err := proto.Unmarshal(decoded, &encryptedSt); err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to marshal encoded/encrypted state", errors.WithWrap(err))
	}

	var blobInfo wrapping.EncryptedBlobInfo
	if err := proto.Unmarshal(encryptedSt.Ct, &blobInfo); err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to marshal blob info", errors.WithWrap(err))
	}

	marshaledSt, err := wrapper.Decrypt(ctx, &blobInfo, nil)
	if err != nil {
		return "", "", nil, errors.New(errors.Encrypt, op, "unable to decrypt state", errors.WithWrap(err))
	}
	var st request.State
	if err := proto.Unmarshal(marshaledSt, &st); err != nil {
		return "", "", nil, errors.New(errors.Unknown, op, "unable to marshal request state", errors.WithWrap(err))
	}

	return encryptedSt.ScopeId, encryptedSt.AuthMethodId, &st, nil
}
