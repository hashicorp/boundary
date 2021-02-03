package oidc

import (
	"context"
)

// AddAudClaims will add audience claims associated with an auth method.  No
// options are currently supported. Zero is not a valid value for the
// authMethodVersion.  The auth method's current db version must match the
// authMethodVersion or an error will be returned. This method is idempotent.
func (r *Repository) AddAudClaims(ctx context.Context, authMethodId string, authMethodVersion uint32, audience []string, _ ...Option) ([]*AudClaim, error) {
	panic("to-do")
}

// DeleteAudClaims will delete matching audience claims associated with an auth
// method.  No options are currently supported.  Zero is not a valid value for
// the authMethodVersion. The auth method's current db version must match the
// authMethodVersion or an error will be returned. This method is idempotent.
func (r *Repository) DeleteAudClaims(ctx context.Context, authMethodId string, authMethodVersion uint32, audience []string, _ ...Option) ([]*AudClaim, error) {
	panic("to-do")
}

// SetAudClaims will set the audience claims associated with an auth method
// (adding and deleted as needed). No options are currently supported.  Zero is
// not a valid value for the authMethodVersion. The auth method's current db
// version must match the authMethodVersion or an error will be returned. This
// method is idempotent.
func (r *Repository) SetAudClaims(ctx context.Context, authMethodId string, authMethodVersion uint32, audience []string, _ ...Option) ([]*AudClaim, error) {
	panic("to-do")
}

// ListAudClaims returns the audience claims for the auth method and supports
// the WithLimit option.
func (r *Repository) ListAudClaims(ctx context.Context, authMethodId string, authMethodVersion uint32, opt ...Option) ([]*AudClaim, error) {
	panic("to-do")
}
