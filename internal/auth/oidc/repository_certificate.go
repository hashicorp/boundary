package oidc

import (
	"context"
	"crypto/x509"
)

// AddCertificates will add certificates associated with an auth method.  No
// options are currently supported. Zero is not a valid value for the
// authMethodVersion.  The auth method's current db version must match the
// authMethodVersion or an error will be returned. This method is idempotent.
func (r *Repository) AddCertificates(ctx context.Context, authMethodId string, authMethodVersion uint32, cert []*x509.Certificate, _ ...Option) ([]*Certificate, error) {
	panic("to-do")
}

// DeleteCertificates will delete matching certificates associated with an auth
// method.  No options are currently supported.  Zero is not a valid value for
// the authMethodVersion. The auth method's current db version must match the
// authMethodVersion or an error will be returned. This method is idempotent.
func (r *Repository) DeleteCertificates(ctx context.Context, authMethodId string, authMethodVersion uint32, cert []*x509.Certificate, _ ...Option) ([]*Certificate, error) {
	panic("to-do")
}

// SetCertificates will set the certificates associated with an auth method
// (adding and deleted as needed). No options are currently supported.  Zero is
// not a valid value for the authMethodVersion. The auth method's current db
// version must match the authMethodVersion or an error will be returned. This
// method is idempotent.
func (r *Repository) SetCertificates(ctx context.Context, authMethodId string, authMethodVersion uint32, cert []*x509.Certificate, _ ...Option) ([]*Certificate, error) {
	panic("to-do")
}

// ListCertificates returns the certificates for the auth method and supports
// the WithLimit option.
func (r *Repository) ListCertificates(ctx context.Context, authMethodId string, authMethodVersion uint32, opt ...Option) ([]*Certificate, error) {
	panic("to-do")
}
