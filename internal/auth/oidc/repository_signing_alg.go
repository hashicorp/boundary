package oidc

import (
	"context"
)

// AddSigningAlgs will add signing algorithms associated with an auth method.  No
// options are currently supported. Zero is not a valid value for the
// authMethodVersion.  The auth method's current db version must match the
// authMethodVersion or an error will be returned. This method is idempotent.
func (r *Repository) AddSigningAlgs(ctx context.Context, authMethodId string, authMethodVersion uint32, alg []SigningAlg, _ ...Option) ([]*SigningAlg, error) {
	panic("to-do")
}

// DeleteSigningAlgs will delete matching signing algorithms associated with an auth
// method.  No options are currently supported.  Zero is not a valid value for
// the authMethodVersion. The auth method's current db version must match the
// authMethodVersion or an error will be returned. This method is idempotent.
func (r *Repository) DeleteSigningAlgs(ctx context.Context, authMethodId string, authMethodVersion uint32, alg []SigningAlg, _ ...Option) ([]*SigningAlg, error) {
	panic("to-do")
}

// SetSigningAlgs will set the signing algorithms associated with an auth method
// (adding and deleted as needed). No options are currently supported.  Zero is
// not a valid value for the authMethodVersion. The auth method's current db
// version must match the authMethodVersion or an error will be returned. This
// method is idempotent.
func (r *Repository) SetSigningAlgs(ctx context.Context, authMethodId string, authMethodVersion uint32, alg []SigningAlg, _ ...Option) ([]*SigningAlg, error) {
	panic("to-do")
}

// ListSigningAlgs returns the signing algorithms for the auth method and supports
// the WithLimit option.
func (r *Repository) ListSigningAlgs(ctx context.Context, authMethodId string, authMethodVersion uint32, opt ...Option) ([]*SigningAlg, error) {
	panic("to-do")
}
