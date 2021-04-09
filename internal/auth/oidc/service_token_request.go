package oidc

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"google.golang.org/protobuf/proto"
)

// TokenRequest is an oidc domain service function for processing a token
// request from a Boundary client.  Token requests are the result of a Boundary
// client polling the tokenUrl they received via StartAuth.  On success, it
// returns Boundary token.
//
// * Decrypt the tokenRequestId.  If encryption fails, it returns an error.
//
// * Use the authtoken.(Repository).IssueAuthToken to issue the request id's
// token and mark it as issued in the repo.  If the token is already issue, an
// error is returned.
func TokenRequest(ctx context.Context, kms *kms.Kms, atRepoFn AuthTokenRepoFactory, tokenRequestId string) (*authtoken.AuthToken, error) {
	const op = "oidc.TokenRequest"
	if kms == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing kms")
	}
	if atRepoFn == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing auth token repo function")
	}

	reqTkWrapper, err := unwrapMessage(ctx, tokenRequestId)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	if reqTkWrapper.ScopeId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "request token id wrapper missing scope id")
	}
	if reqTkWrapper.AuthMethodId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "request token id wrapper missing auth method id")
	}

	// tokenRequestId is a proto request.Wrapper, which contains a cipher text field,
	// so we need the derived wrapper that was used to encrypt it.
	requestWrapper, err := requestWrappingWrapper(ctx, kms, reqTkWrapper.ScopeId, reqTkWrapper.AuthMethodId)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	reqTkBytes, err := decryptMessage(ctx, requestWrapper, reqTkWrapper)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	var reqTk request.Token
	if err := proto.Unmarshal(reqTkBytes, &reqTk); err != nil {
		return nil, errors.New(errors.Unknown, op, "unable to unmarshal request token", errors.WithWrap(err))
	}

	if reqTk.ExpirationTime == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing request token id expiration time")
	}

	// before proceeding, make sure the request hasn't timed out
	if time.Now().After(reqTk.ExpirationTime.Timestamp.AsTime()) {
		return nil, errors.New(errors.AuthAttemptExpired, op, "request token id has expired")
	}

	tokenRepo, err := atRepoFn()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	authTk, err := tokenRepo.IssueAuthToken(ctx, reqTk.RequestId)
	if err != nil {
		if errors.Match(errors.T(errors.RecordNotFound), err) {
			// We don't have it -- at least not yet. So don't mark it as an
			// error, but nothing is returned.
			return nil, nil
		}
		return nil, errors.Wrap(err, op)
	}
	if authTk.Token == "" {
		return nil, errors.New(errors.Internal, op, "issued token is missing")
	}
	return authTk, nil
}
