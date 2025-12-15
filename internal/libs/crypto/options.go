// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package crypto

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) (*options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			if err := o(opts); err != nil {
				return nil, err
			}
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments.
type Option func(*options) error

// options = how options are represented
type options struct {
	withPrefix         string
	withPrk            []byte
	withEd25519        bool
	withBase64Encoding bool
	withBase58Encoding bool
}

func getDefaultOptions() *options {
	return &options{}
}

// WithPrefix allows an optional prefix to be specified for the data returned
func WithPrefix(prefix string) Option {
	return func(o *options) error {
		o.withPrefix = prefix
		return nil
	}
}

// WithPrk allows an optional PRK (pseudorandom key) to be specified for an
// operation.  If you're using this option with HmacSha256, you might consider
// using HmacSha256WithPrk instead.
func WithPrk(prk []byte) Option {
	return func(o *options) error {
		o.withPrk = prk
		return nil
	}
}

// WithEd25519 allows an optional request to use ed25519 during the operation
func WithEd25519() Option {
	return func(o *options) error {
		o.withEd25519 = true
		return nil
	}
}

// WithBase64Encoding allows an optional request to base64 encode the data returned
func WithBase64Encoding() Option {
	return func(o *options) error {
		o.withBase64Encoding = true
		return nil
	}
}

// WithBase58Encoding allows an optional request to base58 encode the data returned
func WithBase58Encoding() Option {
	return func(o *options) error {
		o.withBase58Encoding = true
		return nil
	}
}
