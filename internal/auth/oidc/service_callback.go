package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/cap/oidc"
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
		return "", errors.Wrap(err, op)
	}
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	if am == nil {
		return "", errors.New(errors.RecordNotFound, op, fmt.Sprintf("auth method %s not found", authMethodId))
	}

	// state is a proto request.Wrapper msg, which contains a cipher text field, so
	// we need the derived wrapper that was used to encrypt it.
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

	// get the provider from the cache (if possible).  FYI: "get" just does the right thing
	// about comparing the cache with the auth method from the db.
	provider, err := providerCache().get(ctx, am)
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	// if auth method is inactive, we don't allow inflight requests to finish if the
	// auth method's config has changed since the request was kicked off.
	hash, err := provider.ConfigHash()
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to get provider config hash", errors.WithWrap(err))
	}
	if reqState.ProviderConfigHash != hash && am.OperationalState == string(InactiveState) {
		return "", errors.New(errors.AuthMethodInactive, op, "auth method configuration changed during in-flight authentication attempt")
	}

	// before proceeding, make sure the request hasn't timed out
	if time.Now().After(reqState.ExpirationTime.Timestamp.AsTime()) {
		return "", errors.New(errors.AuthAttemptExpired, op, "request state has expired")
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
	if len(am.CallbackUrls) != 1 {
		return "", errors.New(errors.InvalidParameter, op, fmt.Sprintf("expected 1 callback URL and got: %d", len(am.CallbackUrls)))
	}
	oidcRequest, err := oidc.NewRequest(AttemptExpiration, fmt.Sprintf(CallbackEndpoint, am.CallbackUrls[0], am.PublicId), opts...)
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to create oidc request for token exchange", errors.WithWrap(err))
	}
	tk, err := provider.Exchange(ctx, oidcRequest, state, code)
	if err != nil {
		return "", errors.New(errors.Unknown, op, "unable to complete exchange with oidc provider", errors.WithWrap(err))
	}

	// okay, now we need some claims from both the ID Token and userinfo, so we can
	// upsert an auth account
	idTkClaims := map[string]interface{}{}     // intentionally, NOT nil for call to upsertAccount(...)
	userInfoClaims := map[string]interface{}{} // intentionally, NOT nil for call to upsertAccount(...)

	if err := tk.IDToken().Claims(&idTkClaims); err != nil {
		return "", errors.New(errors.Unknown, op, "unable to parse ID Token claims", errors.WithWrap(err))
	}

	userInfoTokenSource := tk.StaticTokenSource()
	if userInfoTokenSource != nil {
		sub, ok := idTkClaims["sub"].(string)
		if !ok {
			return "", errors.New(errors.Unknown, op, "subject is not present in ID Token, which should not be possible")
		}
		if err := provider.UserInfo(ctx, userInfoTokenSource, sub, &userInfoClaims); err != nil {
			return "", errors.New(errors.Unknown, op, "unable to get user info from provider", errors.WithWrap(err))
		}
	}

	acct, err := r.upsertAccount(ctx, am, idTkClaims, userInfoClaims)
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	// before searching for the iam.User associated with the account,
	// we need to see if this particular auth method is allowed to
	// autovivify users for the scope.
	iamRepo, err := iamRepoFn()
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	scope, err := iamRepo.LookupScope(ctx, am.ScopeId)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("unable to lookup account scope: "+scope.PublicId))
	}

	user, err := iamRepo.LookupUserWithLogin(ctx, acct.PublicId)
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	// wow, we're getting close.  we just need to create a pending token for this
	// successful authentication process, so it can be retrieved by the polling client
	// that initialed the authentication attempt.
	tokenRepo, err := atRepoFn()
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	if _, err := tokenRepo.CreateAuthToken(ctx, user, acct.PublicId, authtoken.WithPublicId(reqState.TokenRequestId), authtoken.WithStatus(authtoken.PendingStatus)); err != nil {
		if errors.Match(errors.T(errors.NotUnique), err) {
			return "", errors.New(errors.Forbidden, op, "not a unique request", errors.WithWrap(err))
		}
		return "", errors.Wrap(err, op)
	}
	// tada!  we can return a final redirect URL for the successful authentication.
	return reqState.FinalRedirectUrl, nil
}
