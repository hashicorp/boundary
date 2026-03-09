// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

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
	withName                 string
	withDescription          string
	withLimit                int
	withPublicId             string
	withPrivateKeyPassphrase []byte
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

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are
// returned. If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}

// WithPublicId provides an optional public ID to use.
func WithPublicId(name string) Option {
	return func(o *options) {
		o.withPublicId = name
	}
}

// WithPrivateKeyPassphrase provides an optional SSH private key passphrase to use.
func WithPrivateKeyPassphrase(with []byte) Option {
	return func(o *options) {
		o.withPrivateKeyPassphrase = with
	}
}
