// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// StartAuth accepts a request to start an OIDC authentication/authorization
// attempt. It returns two URLs and a tokenId.  authUrl is an OIDC authorization
// request URL. The authUrl includes a "state" parameter which is encrypted and
// has a payload which includes (among other things) the final redirect
// (calculated from the clientInfo), a token_request_id, and nonce. The tokenUrl
// is the URL theclient can use to retrieve the results of the user's OIDC
// authentication attempt. The tokenId is an encrypted payload for the POST
// request to the tokenUrl.
//
// If the auth method is in an InactiveState, then an error is returned.
//
// Options supported:
//
// WithRoundTripPayload(string) provides an option for a client roundtrip
// payload. This payload will be added to the final redirect as a query
// parameter.
func StartAuth(ctx context.Context, oidcRepoFn OidcRepoFactory, authMethodId string, opt ...Option) (authUrl *url.URL, tokenId string, e error) {
	const op = "oidc.StartAuth"
	if authMethodId == "" {
		return nil, "", errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if oidcRepoFn == nil {
		return nil, "", errors.New(ctx, errors.InvalidParameter, op, "missing oidc repo function")
	}
	r, err := oidcRepoFn()
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	if am == nil {
		return nil, "", errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("auth method %s not found", authMethodId))
	}
	if am.OperationalState == string(InactiveState) {
		return nil, "", errors.New(ctx, errors.AuthMethodInactive, op, "not allowed to start authentication attempt")
	}
	if len(am.Prompts) > 0 {
		prompts := strutil.RemoveDuplicatesStable(am.Prompts, false)

		if strutil.StrListContains(prompts, string(oidc.None)) && len(prompts) > 1 {
			return nil, "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf(`prompts (%s) includes "none" with other values`, am.Prompts))
		}
	}

	// get the provider from the cache (if possible)
	provider, err := providerCache().get(ctx, am)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	callbackRedirect := fmt.Sprintf(CallbackEndpoint, am.GetApiUrl())

	opts := getOpts(opt...)
	finalRedirect := fmt.Sprintf(FinalRedirectEndpoint, am.GetApiUrl())
	if opts.withRoundtripPayload != "" {
		u := make(url.Values)
		u.Add("roundtrip_payload", opts.withRoundtripPayload)
		finalRedirect = fmt.Sprintf("%s?%s", finalRedirect, u.Encode())
	}
	now := time.Now()
	createTime := timestamppb.New(now.Truncate(time.Second))
	exp := timestamppb.New(now.Add(AttemptExpiration).Truncate(time.Second))
	tokenRequestId, err := authtoken.NewAuthTokenId(ctx)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	nonce, err := oidc.NewID()
	if err != nil {
		return nil, "", errors.New(ctx, errors.Unknown, op, "unable to generate nonce", errors.WithWrap(err))
	}
	hash, err := provider.ConfigHash()
	if err != nil {
		return nil, "", errors.New(ctx, errors.Unknown, op, "unable to get provider config hash", errors.WithWrap(err))
	}
	st := &request.State{
		TokenRequestId:     tokenRequestId,
		CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
		ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
		FinalRedirectUrl:   finalRedirect,
		Nonce:              nonce,
		ProviderConfigHash: hash,
	}

	requestWrapper, err := requestWrappingWrapper(ctx, r.kms, am.ScopeId, authMethodId)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	encodedEncryptedSt, err := encryptMessage(ctx, requestWrapper, am, st)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	oidcOpts := []oidc.Option{
		oidc.WithState(string(encodedEncryptedSt)),
		oidc.WithNonce(nonce),
	}
	switch {
	case am.MaxAge == -1:
		oidcOpts = append(oidcOpts, oidc.WithMaxAge(0))
	case am.MaxAge > 0:
		oidcOpts = append(oidcOpts, oidc.WithMaxAge(uint(am.MaxAge)))
	default:
	}

	if len(am.ClaimsScopes) > 0 {
		oidcOpts = append(oidcOpts, oidc.WithScopes(am.ClaimsScopes...))
	}

	if len(am.Prompts) > 0 {
		prompts := convertToOIDCPrompts(ctx, am.Prompts)
		oidcOpts = append(oidcOpts, oidc.WithPrompts(prompts...))
	}

	// a bare min oidc.Request needed for the provider.AuthURL(...) call.  We've intentionally not populated
	// things like Audiences, because this oidc.Request isn't cached and not intended for use in future legs
	// of the authen flow.
	oidcReq, err := oidc.NewRequest(
		AttemptExpiration,
		callbackRedirect,
		oidcOpts...)
	if err != nil {
		return nil, "", errors.New(ctx, errors.Unknown, op, "unable to create oidc request", errors.WithWrap(err))
	}

	u, err := provider.AuthURL(ctx, oidcReq)
	if err != nil {
		return nil, "", errors.New(ctx, errors.Unknown, op, "unable to get auth url from provider", errors.WithWrap(err))
	}
	authUrl, err = url.Parse(u)
	if err != nil {
		return nil, "", errors.New(ctx, errors.Unknown, op, "unable to parse auth url", errors.WithWrap(err))
	}

	t := &request.Token{
		RequestId:      tokenRequestId,
		ExpirationTime: &timestamp.Timestamp{Timestamp: exp},
	}
	encodedEncryptedTk, err := encryptMessage(ctx, requestWrapper, am, t)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	return authUrl, encodedEncryptedTk, nil
}
