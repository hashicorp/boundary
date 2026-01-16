// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-bexpr"
	"github.com/mitchellh/pointerstructure"
	"google.golang.org/protobuf/proto"
)

// Callback is an oidc domain service function for processing a successful OIDC
// Authentication Response from an IdP oidc callback. On success, it returns a
// final redirect URL for the response to the IdP.
//
// Callback can return several errors including errors.Forbidden for requests
// with non-unique states (which are replays)
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
	atRepoFn AuthTokenRepoFactory,
	am *AuthMethod,
	state, code string,
) (finalRedirect string, e error) {
	const op = "oidc.Callback"
	if oidcRepoFn == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing oidc repository function")
	}
	if iamRepoFn == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing iam repository function")
	}
	if atRepoFn == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing auth token repository function")
	}
	if am == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	}
	if state == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing state")
	}
	if code == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing code")
	}

	// One comment before we begin, Callback orchestrates repositories which
	// execute order dependent database transactions: create an account,
	// perhaps create an iam.User, and if everything is successful it will
	// create a pending token.  Any of these independent transactions could
	// fail, but we don't need to undo a previous successful transactions
	// in the Callback.  The sequentially order transactions all leave the
	// database is a consistent state, even if subsequent transactions fail.
	// Future requests will not be hampered by previous unsuccessful Callback
	// operations.

	r, err := oidcRepoFn()
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}

	// state is a proto request.Wrapper msg, which contains a cipher text field, so
	// we need the derived wrapper that was used to encrypt it.
	requestWrapper, err := requestWrappingWrapper(ctx, r.kms, am.ScopeId, am.GetPublicId())
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	stateWrapper, err := UnwrapMessage(ctx, state)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}

	// it appears the authentication request was started with one auth method
	// and the callback came to a different auth method.
	if stateWrapper.AuthMethodId != am.GetPublicId() {
		return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s auth method id does not match request wrapper auth method id: %s", am.GetPublicId(), stateWrapper))
	}

	stateBytes, err := decryptMessage(ctx, requestWrapper, stateWrapper)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	var reqState request.State
	if err := proto.Unmarshal(stateBytes, &reqState); err != nil {
		return "", errors.New(ctx, errors.Unknown, op, "unable to unmarshal request state", errors.WithWrap(err))
	}

	// get the provider from the cache (if possible).  FYI: "get" just does the right thing
	// about comparing the cache with the auth method from the db.
	provider, err := providerCache().get(ctx, am)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}

	// if auth method is inactive, we don't allow inflight requests to finish if the
	// auth method's config has changed since the request was kicked off.
	hash, err := provider.ConfigHash()
	if err != nil {
		return "", errors.New(ctx, errors.Unknown, op, "unable to get provider config hash", errors.WithWrap(err))
	}
	if reqState.ProviderConfigHash != hash && am.OperationalState == string(InactiveState) {
		return "", errors.New(ctx, errors.AuthMethodInactive, op, "auth method configuration changed during in-flight authentication attempt")
	}

	// before proceeding, make sure the request hasn't timed out
	if time.Now().After(reqState.ExpirationTime.Timestamp.AsTime()) {
		return "", errors.New(ctx, errors.AuthAttemptExpired, op, "request state has expired")
	}

	// now, we need to prep for the token exchange with the oidc provider, which
	// means sort of re-creating the orig oidc.Request with enough info to properly
	// validate the ID Token
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
	if strings.TrimSpace(am.ApiUrl) == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "empty api URL")
	}
	oidcRequest, err := oidc.NewRequest(AttemptExpiration, fmt.Sprintf(CallbackEndpoint, am.ApiUrl), opts...)
	if err != nil {
		return "", errors.New(ctx, errors.Unknown, op, "unable to create oidc request for token exchange", errors.WithWrap(err))
	}
	tk, err := provider.Exchange(ctx, oidcRequest, state, code)
	if err != nil {
		return "", errors.New(ctx, errors.Unknown, op, "unable to complete exchange with oidc provider", errors.WithWrap(err))
	}

	// okay, now we need some claims from both the ID Token and userinfo, so we can
	// upsert an auth account
	idTkClaims := map[string]any{}     // intentionally, NOT nil for call to upsertAccount(...)
	userInfoClaims := map[string]any{} // intentionally, NOT nil for call to upsertAccount(...)

	if err := tk.IDToken().Claims(&idTkClaims); err != nil {
		return "", errors.New(ctx, errors.Unknown, op, "unable to parse ID Token claims", errors.WithWrap(err))
	}

	userInfoTokenSource := tk.StaticTokenSource()
	if userInfoTokenSource != nil {
		sub, ok := idTkClaims["sub"].(string)
		if !ok {
			return "", errors.New(ctx, errors.Unknown, op, "subject is not present in ID Token, which should not be possible")
		}
		if err := provider.UserInfo(ctx, userInfoTokenSource, sub, &userInfoClaims); err != nil {
			return "", errors.New(ctx, errors.Unknown, op, "unable to get user info from provider", errors.WithWrap(err))
		}
	}

	acct, err := r.upsertAccount(ctx, am, idTkClaims, userInfoClaims)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}

	// Get the set of all managed groups so we can filter
	mgs, _, err := r.ListManagedGroups(ctx, am.GetPublicId(), WithLimit(-1))
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	if len(mgs) > 0 {
		matchedMgs := make([]*ManagedGroup, 0, len(mgs))
		evalData := map[string]any{
			"token":    idTkClaims,
			"userinfo": userInfoClaims,
		}
		// Iterate through and check claims against filters
		for _, mg := range mgs {
			eval, err := bexpr.CreateEvaluator(mg.Filter)
			if err != nil {
				// We check all filters on ingress so this should never happen,
				// but we validate anyways
				return "", errors.Wrap(ctx, err, op)
			}
			match, err := eval.Evaluate(evalData)
			if err != nil && !errors.Is(err, pointerstructure.ErrNotFound) {
				return "", errors.Wrap(ctx, err, op)
			}
			if match {
				matchedMgs = append(matchedMgs, mg)
			}
		}
		// We always pass it in, even if none match, because in that case we
		// need to remove any mappings that exist
		if _, _, err := r.SetManagedGroupMemberships(ctx, am, acct, matchedMgs); err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
	}

	// before searching for the iam.User associated with the account,
	// we need to see if this particular auth method is allowed to
	// autovivify users for the scope.
	iamRepo, err := iamRepoFn()
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}

	_, err = iamRepo.LookupScope(ctx, am.ScopeId)
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup account scope: "+am.ScopeId))
	}

	user, err := iamRepo.LookupUserWithLogin(ctx, acct.PublicId)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}

	// Now we need to check filters and assign managed groups by filter.

	// wow, we're getting close.  we just need to create a pending token for this
	// successful authentication process, so it can be retrieved by the polling client
	// that initialed the authentication attempt.
	tokenRepo, err := atRepoFn()
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	authToken, err := tokenRepo.CreateAuthToken(ctx, user, acct.PublicId, authtoken.WithPublicId(reqState.TokenRequestId), authtoken.WithStatus(authtoken.PendingStatus))
	if err != nil {
		if errors.Match(errors.T(errors.NotUnique), err) {
			return "", errors.New(ctx, errors.Forbidden, op, "not a unique request", errors.WithWrap(err))
		}
		return "", errors.Wrap(ctx, err, op)
	}
	if err := event.WriteObservation(ctx, op, event.WithDetails("user_id", user.GetPublicId(), "auth_token_start",
		authToken.GetCreateTime(), "auth_token_end", authToken.GetExpirationTime())); err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("Unable to write observation event for authenticate method"))
	}
	// tada!  we can return a final redirect URL for the successful authentication.
	return reqState.FinalRedirectUrl, nil
}
