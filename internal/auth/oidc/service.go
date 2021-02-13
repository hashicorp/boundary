package oidc

import (
	"context"
	"net/url"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
)

type (
	// OidcRepoFactory creates a new oidc repo
	OidcRepoFactory func() (*Repository, error)

	// IamRepoFactory creates a new iam repo
	IamRepoFactory func() (*iam.Repository, error)

	// AuthTokenRepFactory creates a new auth token repo
	AuthTokenRepFactory func() (*authtoken.Repository, error)
)

// ClientInfo contains client info provide during oidc operations.
type ClientInfo struct {
	Type         string
	Version      string
	RoundTripKVs map[string]string
}

// StartAuth accepts a request to start an OIDC authentication/authorization
// attempt.  It returns two URLs.  authUrl is an OIDC authorization request URL.
// The authUrl includes a "state" parameter which is encrypted and has a payload
// which includes (among other things) the final redirect (calculated from the
// clientInfo), a token_request_id,  and nonce. The tokenUrl is the URL the
// client can use to retrieve the results of the user's OIDC authentication
// attempt. The tokenUrl contains a token_request_id, which is encrypted. No
// options are currently supported.
func StartAuth(ctx context.Context, kms *kms.Kms, authMethodId string, clientInfo ClientInfo) (authUrl *url.URL, tokenUrl *url.URL, e error) {
	panic("to-do")
}

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
	kms *kms.Kms,
	oidcRepoFn OidcRepoFactory,
	iamRepoFn IamRepoFactory,
	atRepoFn AuthTokenRepFactory,
	authMethodId, state, code string) (finalRedirect string, e error) {
	panic("to-do")
}

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
func TokenRequest(ctx context.Context, kms *kms.Kms, atRepoFn AuthTokenRepFactory, tokenRequestId string) (string, error) {
	panic("to-do")
}
