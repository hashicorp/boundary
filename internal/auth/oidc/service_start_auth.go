package oidc

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/cap/oidc"
)

// StartAuth accepts a request to start an OIDC authentication/authorization
// attempt.  It returns two URLs.  authUrl is an OIDC authorization request URL.
// The authUrl includes a "state" parameter which is encrypted and has a payload
// which includes (among other things) the final redirect (calculated from the
// clientInfo), a token_request_id,  and nonce. The tokenUrl is the URL the
// client can use to retrieve the results of the user's OIDC authentication
// attempt. The tokenUrl contains a token_request_id, which is encrypted.
//
// Options supported:
//
// WithRoundTripPayload(string) provides an option for a client roundtrip
// payload.  This payload will be added to the final redirect as a query
// parameter.
func StartAuth(ctx context.Context, oidcRepoFn OidcRepoFactory, kms *kms.Kms, apiAddr string, authMethodId string, opt ...Option) (authUrl *url.URL, tokenUrl *url.URL, e error) {
	const op = "oidc.StartAuth"
	if apiAddr == "" {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing api address")
	}
	if kms == nil {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing kms")
	}
	if authMethodId == "" {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	r, err := oidcRepoFn()
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	if am == nil {
		return nil, nil, errors.New(errors.RecordNotFound, op, fmt.Sprintf("auth method %s not found", authMethodId))
	}
	provider, err := convertToProvider(ctx, am)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	callbackRedirect := fmt.Sprintf("%s/%s", apiAddr, CallbackEndpoint)

	opts := getOpts(opt...)
	finalRedirect := fmt.Sprintf("%s/%s", apiAddr, FinalRedirectEndpoint)
	if opts.withRoundtripPayload != "" {
		finalRedirect = fmt.Sprintf("%s?%s", finalRedirect, opts.withRoundtripPayload)
	}
	now := time.Now()
	createTime, err := ptypes.TimestampProto(now.Truncate(time.Second))
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "create timestamp failed", errors.WithWrap(err))
	}
	exp, err := ptypes.TimestampProto(now.Add(AttemptExpiration).Truncate(time.Second))
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "exp timestamp failed", errors.WithWrap(err))
	}
	tokenRequestId, err := authtoken.NewAuthTokenId()
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	nonce, err := oidc.NewID()
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to generate nonce", errors.WithWrap(err))
	}
	hash, err := provider.ConfigHash()
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to get provider config hash", errors.WithWrap(err))
	}
	st := &request.State{
		TokenRequestId:     tokenRequestId,
		CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
		ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
		FinalRedirectUrl:   finalRedirect,
		Nonce:              nonce,
		ProviderConfigHash: hash,
	}

	stateWrapper, err := r.stateWrapper(ctx, am.ScopeId, authMethodId)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	encodedEncryptedSt, err := encryptMessage(ctx, stateWrapper, am, st)
	if err != nil {
		return nil, nil, errors.Wrap(err, op)
	}
	// a bare min oidc.Request needed for the provider.AuthURL(...) call.  We've intentionally not populated
	// things like Audiences, because this oidc.Request isn't cached and not intended for use in future legs
	// of the authen flow.
	oidcReq, err := oidc.NewRequest(
		AttemptExpiration,
		callbackRedirect,
		oidc.WithState(string(encodedEncryptedSt)),
		oidc.WithNonce(nonce))
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to create oidc request", errors.WithWrap(err))
	}

	u, err := provider.AuthURL(ctx, oidcReq)
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to get auth url from provider", errors.WithWrap(err))
	}
	authUrl, err = url.Parse(u)
	if err != nil {
		return nil, nil, errors.New(errors.Unknown, op, "unable to parse auth url", errors.WithWrap(err))
	}

	return authUrl, tokenUrl, nil
}
