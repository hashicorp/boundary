package oidc

import (
	"context"
	"net/url"
)

// AddCallbackUrls will add callback URLs associated with an auth method.  No
// options are currently supported. Zero is not a valid value for the
// authMethodVersion.  The auth method's current db version must match the
// authMethodVersion or an error will be returned. This method is idempotent.
func (r *Repository) AddCallbackUrls(ctx context.Context, authMethodId string, authMethodVersion uint32, urls []*url.URL, _ ...Option) {
	panic("to-do")
}

// DeleteCallbackUrls will delete matching callback URLs associated with an auth
// method.  No options are currently supported.  Zero is not a valid value for
// the authMethodVersion. The auth method's current db version must match the
// authMethodVersion or an error will be returned. This method is idempotent.
func (r *Repository) DeleteCallbackUrls(ctx context.Context, authMethodId string, authMethodVersion uint32, urls []*url.URL, _ ...Option) {
	panic("to-do")
}

// SetCallbackUrls will set the callback URLs associated with an auth method
// (adding and deleted as needed). No options are currently supported.  Zero is
// not a valid value for the authMethodVersion. The auth method's current db
// version must match the authMethodVersion or an error will be returned. This
// method is idempotent.
func (r *Repository) SetCallbackUrls(ctx context.Context, authMethodId string, authMethodVersion uint32, urls []*url.URL, _ ...Option) {
	panic("to-do")
}

// ListCallbackUrls returns the callback URLs for the auth method and supports
// the WithLimit option.
func (r *Repository) ListCallbackUrls(ctx context.Context, authMethodId string, authMethodVersion uint32, opt ...Option) ([]*CallbackUrl, error) {
	panic("to-do")
}
