// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import "github.com/hashicorp/boundary/internal/credential"

// getOpts - iterate the inbound Options and return a struct
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
	withName           string
	withDescription    string
	withLimit          int
	withCACert         []byte
	withNamespace      string
	withTlsServerName  string
	withTlsSkipVerify  bool
	withWorkerFilter   string
	withClientCert     *ClientCertificate
	withMethod         Method
	withRequestBody    []byte
	withCredentialType credential.Type

	withOverrideUsernameAttribute             string
	withOverridePasswordAttribute             string
	withOverridePrivateKeyAttribute           string
	withOverridePrivateKeyPassphraseAttribute string
	withMappingOverride                       MappingOverride

	withKeyType         string
	withKeyBits         uint32
	withTtl             string
	withKeyId           string
	withCriticalOptions string
	withExtensions      string
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

// WithWorkerFilter provides an optional worker filter.
func WithWorkerFilter(filter string) Option {
	return func(o *options) {
		o.withWorkerFilter = filter
	}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are
// returned. If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}

// WithCACert provides an optional PEM-encoded certificate
// to verify the Vault server's SSL certificate.
func WithCACert(cert []byte) Option {
	return func(o *options) {
		o.withCACert = cert
	}
}

// WithNamespace provides an optional Vault namespace.
func WithNamespace(namespace string) Option {
	return func(o *options) {
		o.withNamespace = namespace
	}
}

// WithTlsServerName provides an optional name to use as the SNI host when
// connecting to Vault via TLS.
func WithTlsServerName(name string) Option {
	return func(o *options) {
		o.withTlsServerName = name
	}
}

// WithTlsSkipVerify provides an option to disable verification of TLS
// certificates when connection to Vault. Using this option is highly
// discouraged as it decreases the security of data transmissions to and
// from the Vault server.
func WithTlsSkipVerify(skipVerify bool) Option {
	return func(o *options) {
		o.withTlsSkipVerify = skipVerify
	}
}

// WithClientCert provides an optional ClientCertificate to use for TLS
// authentication to a Vault server.
func WithClientCert(clientCert *ClientCertificate) Option {
	return func(o *options) {
		o.withClientCert = clientCert
	}
}

// WithMethod provides an optional Method to use for communicating with
// Vault.
func WithMethod(m Method) Option {
	return func(o *options) {
		o.withMethod = m
	}
}

// WithRequestBody provides an optional request body for sending to Vault
// when requesting credentials using HTTP Post.
func WithRequestBody(b []byte) Option {
	return func(o *options) {
		o.withRequestBody = b
	}
}

// WithCredentialType provides an optional credential type to associate
// with a credential library.
func WithCredentialType(t credential.Type) Option {
	return func(o *options) {
		o.withCredentialType = t
	}
}

// WithOverrideUsernameAttribute provides the name of an attribute in the
// Data field of a Vault api.Secret that maps to a username value.
func WithOverrideUsernameAttribute(s string) Option {
	return func(o *options) {
		o.withOverrideUsernameAttribute = s
	}
}

// WithOverridePasswordAttribute provides the name of an attribute in the
// Data field of a Vault api.Secret that maps to a password value.
func WithOverridePasswordAttribute(s string) Option {
	return func(o *options) {
		o.withOverridePasswordAttribute = s
	}
}

// WithOverridePrivateKeyAttribute provides the name of an attribute in the
// Data field of a Vault api.Secret that maps to a private key value.
func WithOverridePrivateKeyAttribute(s string) Option {
	return func(o *options) {
		o.withOverridePrivateKeyAttribute = s
	}
}

// WithOverridePrivateKeyPassphraseAttribute provides the name of an attribute in the
// Data field of a Vault api.Secret that maps to a passphrase value.
func WithOverridePrivateKeyPassphraseAttribute(s string) Option {
	return func(o *options) {
		o.withOverridePrivateKeyPassphraseAttribute = s
	}
}

// WithMappingOverride provides an optional mapping override to use for
// mapping the Data fields of a Vault api.Secret to a credential.
func WithMappingOverride(m MappingOverride) Option {
	return func(o *options) {
		o.withMappingOverride = m
	}
}

// WithKeyType provides an optional ssh private key type to use
// with a ssh certificate credential library. Must be rsa, ed25519, or ecdsa.
func WithKeyType(t string) Option {
	return func(o *options) {
		o.withKeyType = t
	}
}

// WithKeyBits provides an optional number of bits used to generate an ssh private key.
func WithKeyBits(b uint32) Option {
	return func(o *options) {
		o.withKeyBits = b
	}
}

// WithTtl provides an optional requested time to live for a generated ssh certificate.
func WithTtl(t string) Option {
	return func(o *options) {
		o.withTtl = t
	}
}

// WithKeyId provides an optional key id for a created certificate.
func WithKeyId(i string) Option {
	return func(o *options) {
		o.withKeyId = i
	}
}

// WithCriticalOptions provides an optional map of the critical options
// that the certificate should be signed for.
func WithCriticalOptions(s string) Option {
	return func(o *options) {
		o.withCriticalOptions = s
	}
}

// WithExtensions provides a optional map of the extensions
// that the certificate should be signed for.
func WithExtensions(s string) Option {
	return func(o *options) {
		o.withExtensions = s
	}
}
