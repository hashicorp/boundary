// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"crypto/x509"
	"net/url"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
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
	withName                    string
	withDescription             string
	withLimit                   int
	withMaxAge                  int
	withApiUrl                  *url.URL
	withCertificates            []*x509.Certificate
	withAudClaims               []string
	withSigningAlgs             []Alg
	withClaimsScopes            []string
	withPrompts                 []PromptParam
	withEmail                   string
	withFullName                string
	withOrderByCreateTime       bool
	ascending                   bool
	withUnauthenticatedUser     bool
	withForce                   bool
	withDryRun                  bool
	withAuthMethod              *AuthMethod
	withPublicId                string
	withRoundtripPayload        string
	withKeyId                   string
	withIssuer                  *url.URL
	withOperationalState        AuthMethodState
	withAccountClaimMap         map[string]AccountToClaim
	withReader                  db.Reader
	withStartPageAfterItem      pagination.Item
	withoutStrictTypeComparison bool
}

func getDefaultOptions() options {
	return options{
		withOperationalState: InactiveState,
	}
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

// WithApiUrl provides optional api URL to use in the various
func WithApiUrl(urls *url.URL) Option {
	return func(o *options) {
		o.withApiUrl = urls
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

// WithClaimsScopes provides optional claims scopes
func WithClaimsScopes(claimsScope ...string) Option {
	return func(o *options) {
		o.withClaimsScopes = claimsScope
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

// WithOrderByCreateTime provides an option to specify ordering by the
// CreateTime field.
func WithOrderByCreateTime(ascending bool) Option {
	return func(o *options) {
		o.withOrderByCreateTime = true
		o.ascending = ascending
	}
}

// WithUnauthenticatedUser provides an option for filtering results for
// an unauthenticated users.
func WithUnauthenticatedUser(enabled bool) Option {
	return func(o *options) {
		o.withUnauthenticatedUser = enabled
	}
}

// WithForce provides an option to force the write operation, regardless of
// whether or not it's pre-verification succeeds.
func WithForce() Option {
	return func(o *options) {
		o.withForce = true
	}
}

// WithDryRun provides an option to do a "dry run" of a write operation, which
// will run verification steps and return any errors, but will not persist the
// data into the repository.
func WithDryRun() Option {
	return func(o *options) {
		o.withDryRun = true
	}
}

// WithAuthMethod provides an option for passing an AuthMethod to the operation
func WithAuthMethod(am *AuthMethod) Option {
	return func(o *options) {
		o.withAuthMethod = am
	}
}

// WithPublicId provides an option for passing a public id to the operation
func WithPublicId(publicId string) Option {
	return func(o *options) {
		o.withPublicId = publicId
	}
}

// WithRoundTripPayload provides an option for passing an payload to be
// roundtripped during an authentication process.
func WithRoundtripPayload(payload string) Option {
	return func(o *options) {
		o.withRoundtripPayload = payload
	}
}

// WithKeyId provides an option for specifying a key id.
func WithKeyId(id string) Option {
	return func(o *options) {
		o.withKeyId = id
	}
}

// WithIssuer provides an option for specifying an issuer.
func WithIssuer(iss *url.URL) Option {
	return func(o *options) {
		o.withIssuer = iss
	}
}

// WithOperationalState provides an option for specifying an issuer.
func WithOperationalState(state AuthMethodState) Option {
	return func(o *options) {
		o.withOperationalState = state
	}
}

// WithAccountClaimMap provides an option for specifying an Account Claim map.
func WithAccountClaimMap(acm map[string]AccountToClaim) Option {
	return func(o *options) {
		o.withAccountClaimMap = acm
	}
}

// WithReader provides an option for specifying a reader to use for the
// operation.
func WithReader(reader db.Reader) Option {
	return func(o *options) {
		o.withReader = reader
	}
}

// WithPrompts provides optional prompts
func WithPrompts(prompt ...PromptParam) Option {
	return func(o *options) {
		o.withPrompts = prompt
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) {
		o.withStartPageAfterItem = item
	}
}
// WithoutStrictTypeComparison provides an option to disable strict 
// type comparison during filter evaluation.
func WithoutStrictTypeComparison(enabled bool) Option {
	return func(o *options) {
		o.withoutStrictTypeComparison = enabled
	}
}
