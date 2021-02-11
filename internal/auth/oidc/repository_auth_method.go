package oidc

import (
	"context"
	"net/url"
)

// CreateAuthMethod creates m (*AuthMethod) in the repo and returns the newly
// created AuthMethod (with its PublicId set) along with its associated Value
// Objects of SigningAlgs, CallbackUrls, AudClaims (optional) and Certificates
// (optional).
//
// Supported options WithName, WithDescription. All other options are
// ignored.
func (r *Repository) CreateAuthMethod(ctx context.Context, m *AuthMethod, opt ...Option) (*AuthMethod, error) {
	panic("to-do")
}

// LookupAuthMethod will lookup an auth method in the repo, along with its
// associated Value Objects of SigningAlgs, CallbackUrls, AudClaims and
// Certificates. If it's not found, it will return nil, nil.  No options are
// currently supported.
func (r *Repository) LookupAuthMethod(ctx context.Context, publicId string, _ ...Option) (*AuthMethod, error) {
	panic("to-do")
}

// ListAuthMethods returns a slice of AuthMethods for the scopeId. WithLimit is the only option supported.
func (r *Repository) ListAuthMethods(ctx context.Context, scopeIds []string, opt ...Option) ([]*AuthMethod, error) {
	panic("to-do")
}

// DeleteAuthMethod will delete the auth method from the repository.  No options
// are currently supported.
func (r *Repository) DeleteAuthMethod(ctx context.Context, publicId string, _ ...Option) (int, error) {
	panic("to-do")
}

// UpdateAuthMethod will update the auth method in the repository and return the
// written auth method. fieldMaskPaths provides field_mask.proto paths for
// fields that should be updated.  Fields will be set to NULL if the field is a
// zero value and included in fieldMask. Name, Description, State, DiscoveryUrl,
// ClientId, ClientSecret, MaxAge are all updatable fields.  The AuthMethod's
// Value Objects of SigningAlgs, CallbackUrls, AudClaims and Certificates are
// also updatable. if no updatable fields are included in the fieldMaskPaths,
// then an error is returned.  No options are currently supported.
//
// Successful updates must invalidate (delete) the Repository's cache of the
// oidc.Provider for the AuthMethod.
func (r *Repository) UpdateAuthMethod(ctx context.Context, m *AuthMethod, version uint32, fieldMaskPaths []string, _ ...Option) (*AuthMethod, error) {
	panic("to-do")
}

// TestAuthMethod will test/validate the provided AuthMethod.
//
// It will verify that all required fields for a working AuthMethod have values.
//
// If the AuthMethod contains a DiscoveryUrl for an OIDC provider, TestAuthMethod
// retrieves the OpenID Configuration document. The values in the AuthMethod
// (and associated data) are validated with the retrieved document. The issuer and
// id token signing algorithm in the configuration are validated with the
// retrieved document. TestAuthMethod also verifies the authorization, token,
// and user_info endpoints by connecting to each and uses any certificates in the
// configuration as trust anchors to confirm connectivity.
//
// No options are currently supported.
func (r *Repository) TestAuthMethod(ctx context.Context, m *AuthMethod, opt ...Option) error {
	panic("to-do")
}

// MakeInactive will transision an OIDC auth method from either the
// ActivePrivateState or the ActivePublicState into the temporary StoppingState
// and then, after a small amount of time, to the InactiveState.
func (r *Repository) MakeInactive(ctx context.Context, authMethodId string, _ ...Option) error {
	panic("to-do")
}

// MakePrivate will transision an OIDC auth method from either the
// InactiveState or the ActivePublicState into the temporary StoppingState
// and then, after a small amount of time, to the ActivePrivateState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the oidc.TestAuthMethod(...) succeeds. No options are currently supported.
func (r *Repository) MakePrivate(ctx context.Context, authMethodId string, opt ...Option) error {
	panic("to-do")
}

// MakePublic will transision an OIDC auth method from either the
// InactiveState or the ActivePrivateState into the temporary StoppingState
// and then, after a small amount of time, to the ActivePublicState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the oidc.TestAuthMethod(...) succeeds. No options are currently supported.
func (r *Repository) MakePublic(ctx context.Context, authMethodId string, opt ...Option) error {
	panic("to-do")
}

// StartAuth accepts a request to start an OIDC authentication/authorization
// attempt containing the client_type, the client_version, and a map of client
// round-tripper k/v pairs.  It returns two URLs.  authUrl is an OIDC
// authorization request URL.  tokenUrl is the URL the client can use to retrieve
// the results of the user's OIDC authentication attempt.  No options are
// currently supported.
func (r *Repository) StartAuth(ctx context.Context, authMethodId string, clientType, clientVersion string, clientRoundTripKVs map[string]string) (authUrl *url.URL, tokenUrl *url.URL, e error) {
	panic("to-do")
}

// ExchangeAuthResponse exchanges a successful OIDC Authentication Response for
// an ID Token, if the exchange is successful, it returns the Account for the
// user's ID Token sub claim and the client's final redirect URL. If the
// exchange fails, it returns nil and an empty string, along with any error
// that occurred.
//
// The steps that typically follow ExchangeAuthResponse in the callback handler
// should be: iam.LookupUserWithLogin(...) to get the Account's User and then
// authtoken.CreateAuthToken(...) to create a "pending" token for the
// successful.
//
// For more info on a successful OIDC Authentication Response see:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
//
// Operation steps:
//
// * Decrypt the callbackStateParameter which has been encrypted with the OIDC
// DEK. If decryption fails, and error is returned. callbackStateParameter
// decrypted payload includes the token_request_id, nonce and
// final_redirect_url.
//
// * Exchange the callbackCodeParameter for provider tokens and validate the
// tokens.  Call UserInfo endpoint using access token.
//
// * Create/update account using "sub" claim as external ID and setting email
// and full name for the account.
//
// * Return the Account and final redirect URL.
func (r *Repository) ExchangeAuthResponse(ctx context.Context, authMethodId string, callbackStateParameter string, callbackCodeParameter string) (*Account, string, error) {
	panic("to-do")
}

// DecryptTokenRequestId will decrypt the tokenRequestId. The tokenRequestId was
// created and encrypted by the repo's StartAuth(...) function.  If decryption
// fails, an empty string and error is returned.
//
// This function is typically when the auth method service is handling
// "authenticate:token".  If decryption is successful, then the service would
// retrieve the pending token associated with the request id, update the token's
// status to "issued" and return it to the caller.
func (r *Repository) DecryptTokenRequestId(ctx context.Context, tokenRequestId string) (string, error) {
	panic("to-do")
}
