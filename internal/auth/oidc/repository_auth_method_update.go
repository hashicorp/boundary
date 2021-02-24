package oidc

import "context"

// UpdateAuthMethod will retrieve the auth method from the repository,
// update it based on the field masks provided, and then validate it using
// Repository.TestAuthMethod(...).  If the test succeeds, the auth method
// is persisted in the repository and the written auth method is returned.
// fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a
// zero value and included in fieldMask. Name, Description, State, DiscoveryUrl,
// ClientId, ClientSecret, MaxAge are all updatable fields.  The AuthMethod's
// Value Objects of SigningAlgs, CallbackUrls, AudClaims and Certificates are
// also updatable. if no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
//
// Options supported:
//
// * WithDryRun: when this option is provided, the auth method is retrieved from
// the repo, updated based on the fieldMask, tested via Repository.TestAuthMethod
// and any errors reported.  The updates are not peristed to the repository.
//
// * WithForce: when this option is provided, the auth method is persistented in
// the repository without testing it fo validity with Repository.TestAuthMethod.
//
// Successful updates must invalidate (delete) the Repository's cache of the
// oidc.Provider for the AuthMethod.
func (r *Repository) UpdateAuthMethod(ctx context.Context, m *AuthMethod, version uint32, fieldMaskPaths []string, _ ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).UpdateAuthMethod"
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
// Options supported are: WithPublicId, WithAuthMethod
func (r *Repository) TestAuthMethod(ctx context.Context, opt ...Option) error {
	panic("to-do")
}
