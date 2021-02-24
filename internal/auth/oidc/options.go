package oidc

import (
	"crypto/x509"
	"net/url"
)

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withName                string
	withDescription         string
	withLimit               int
	withMaxAge              int
	withCallbackUrls        []*url.URL
	withCertificates        []*x509.Certificate
	withAudClaims           []string
	withSigningAlgs         []Alg
	withEmail               string
	withFullName            string
	withOrderClause         string
	withUnauthenticatedUser bool
}

func getDefaultOptions() options {
	return options{}
}

// WithDescription provides an optional description.
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an optional name.
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}

// WithMaxAge provides an optional max age.   Specifies the allowable elapsed
// time in seconds since the last time the End-User was actively authenticated
// by the OP. If the elapsed time is greater than this value, the OP MUST
// attempt to actively re-authenticate the End-User.  A value -1 basically
// forces the IdP to re-authenticate the End-User.  Zero is not a valid value.
//
// see: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func WithMaxAge(max int) Option {
	return func(o *options) {
		o.withMaxAge = max
	}
}

// WithCallbackUrls provides optional callback URLs.
//
// see redirect_uri:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func WithCallbackUrls(urls ...*url.URL) Option {
	return func(o *options) {
		o.withCallbackUrls = urls
	}
}

// WithCertificates provides optional certificates.
func WithCertificates(certs ...*x509.Certificate) Option {
	return func(o *options) {
		o.withCertificates = certs
	}
}

// WithAudClaims provides optional audience claims
func WithAudClaims(aud ...string) Option {
	return func(o *options) {
		o.withAudClaims = aud
	}
}

// WithSigningAlgs provides optional signing algorithms
func WithSigningAlgs(alg ...Alg) Option {
	return func(o *options) {
		o.withSigningAlgs = alg
	}
}

// WithEmail provides an optional email address for the account.
func WithEmail(email string) Option {
	return func(o *options) {
		o.withEmail = email
	}
}

// WithFullName provides an optional full name for the account.
func WithFullName(n string) Option {
	return func(o *options) {
		o.withFullName = n
	}
}

// WithOrder provides an optional with order clause.
func WithOrder(orderClause string) Option {
	return func(o *options) {
		o.withOrderClause = orderClause
	}
}

// WithUnauthenticatedUser provides an option for filtering results for
// an unauthenticated users.
func WithUnauthenticatedUser(enabled bool) Option {
	return func(o *options) {
		o.withUnauthenticatedUser = enabled
	}
}
