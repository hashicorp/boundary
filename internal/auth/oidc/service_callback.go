package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/cap/oidc"
)

// Callback is an oidc domain service function for processing a successful OIDC
// Authentication Response from an IdP oidc callback. On success, it returns a
// final redirect URL for the response to the IdP.
//
// For more info on a successful OIDC Authentication Response see:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
//
// The service operation includes:
//
// * Decrypt the state which has been encrypted with the OIDC DEK. If decryption
// fails, and error is returned. Decrypted state payload includes the
// token_request_id, nonce and final_redirect_url.
//
// * Exchange the callbackCodeParameter for provider tokens and validate the
// tokens.  Call UserInfo endpoint using access token.
//
// * Use oidc.(Repository).upsertAccount to create/update account using ID
// Tokens claims. The "sub" claim as external ID and setting email and full name
// for the account.
//
// * Use iam.(Repository).LookupUserWithLogin(...) look up the iam.User matching
// the Account.
//
// * Use the authtoken.(Repository).CreateAuthToken(...) to create a pending
// auth token for the authenticated user.
func Callback(
	ctx context.Context,
	oidcRepoFn OidcRepoFactory,
	iamRepoFn IamRepoFactory,
	atRepoFn AuthTokenRepFactory,
	apiAddr,
	authMethodId,
	state, code string) (finalRedirect string, e error) {
	const op = "oidc.Callback"
	if oidcRepoFn == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing oidc repository function")
	}
	if iamRepoFn == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing iam repository function")
	}
	if atRepoFn == nil {
		return "", errors.New(errors.InvalidParameter, op, "missing auth token repository function")
	}
	if authMethodId == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	if state == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing state")
	}
	if code == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing code")
	}
	r, err := oidcRepoFn()
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	if am == nil {
		return "", errors.New(errors.RecordNotFound, op, fmt.Sprintf("auth method %s not found", authMethodId))
	}
	requestWrapper, err := requestWrappingWrapper(ctx, r.kms, am.ScopeId, authMethodId)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	stateWrapper, err := unwrapMessage(ctx, state)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	stateBytes, err := decryptMessage(ctx, requestWrapper, stateWrapper)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	var reqState request.State
	if err := proto.Unmarshal(stateBytes, &reqState); err != nil {
		return "", errors.New(errors.Unknown, op, "unable to unmarshal request state", errors.WithWrap(err))
	}

	// get the provider from the cache (if possible)
	provider, err := providerCache().get(ctx, am)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	hash, err := provider.ConfigHash()
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to get provider config hash", errors.WithWrap(err))
	}
	if reqState.ProviderConfigHash != hash && am.OperationalState == string(InactiveState) {
		return fmt.Sprintf(FinalRedirectEndpoint, apiAddr), nil
	}

	if time.Now().After(reqState.CreateTime.Timestamp.AsTime()) {
		return "", errors.New(errors.AuthAttemptExpired, op, "request state has expired")
	}

	opts := []oidc.Option{
		oidc.WithState(state),
		oidc.WithNonce(reqState.Nonce),
	}
	switch {
	case am.MaxAge == -1:
		opts = append(opts, oidc.WithMaxAge(0))
	case am.MaxAge > 0:
		opts = append(opts, oidc.WithMaxAge(uint(am.MaxAge)))
	default:
	}
	if len(am.AudClaims) > 0 {
		opts = append(opts, oidc.WithAudiences(am.AudClaims...))
	}
	oidcRequest, err := oidc.NewRequest(AttemptExpiration, fmt.Sprintf(CallbackEndpoint, apiAddr, am.PublicId), opts...)
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to create oidc request for token exchange", errors.WithWrap(err))
	}
	tk, err := provider.Exchange(ctx, oidcRequest, state, code)
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to complete exchange with oidc provider", errors.WithWrap(err))
	}
	var claims map[string]interface{}
	if err := tk.IDToken().Claims(claims); err != nil {
		return "", errors.New(errors.Unknown, op, "unable to parse ID Token claims", errors.WithWrap(err))
	}
	acct, err := r.upsertAccount(ctx, am.PublicId, claims)
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	iamRepo, err := iamRepoFn()
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	user, err := iamRepo.LookupUserWithLogin(ctx, acct.PublicId)
	fmt.Println(user)
	panic("to-do")
}
