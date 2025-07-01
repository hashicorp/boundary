// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"errors"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case OptionFunc:
			if err := to(&opts); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("option passed into util wrapping options handler" +
				" that is not from this package; this is likely due to the wrapper being" +
				" invoked as a plugin but options being sent from a specific wrapper package;" +
				" use WithConfigMap to send options via the plugin interface")
		}

	}
	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	withPrefix           string
	withPrk              []byte
	withEd25519          bool
	withBase64Encoding   bool
	withBase58Encoding   bool
	withMarshaledSigInfo bool
	withSalt             []byte
	withInfo             []byte
	WithHexEncoding      bool
}

func getDefaultOptions() options {
	return options{}
}

// WithPrefix allows an optional prefix to be specified for the data returned
func WithPrefix(prefix string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPrefix = prefix
			return nil
		})
	}
}

// WithPrk allows an optional PRK (pseudorandom key) to be specified for an
// operation.  If you're using this option with HmacSha256, you might consider
// using HmacSha256WithPrk instead.
func WithPrk(prk []byte) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPrk = prk
			return nil
		})
	}
}

// WithEd25519 allows an optional request to use ed25519 during the operation
func WithEd25519() wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withEd25519 = true
			return nil
		})
	}
}

// WithBase64Encoding allows an optional request to base64 encode the data returned
func WithBase64Encoding() wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withBase64Encoding = true
			return nil
		})
	}
}

// WithBase58Encoding allows an optional request to base58 encode the data returned
func WithBase58Encoding() wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withBase58Encoding = true
			return nil
		})
	}
}

// WithMarshaledSigInfo allows an optional request to wrap the returned data into
// a marshaled  wrapping.SigInfo protobuf
func WithMarshaledSigInfo() wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withMarshaledSigInfo = true
			return nil
		})
	}
}

// WithSalt allows optional salt to be specified for an operation.
func WithSalt(salt []byte) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSalt = salt
			return nil
		})
	}
}

// WithInfo allows optional info to be specified for an operation.
func WithInfo(info []byte) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withInfo = info
			return nil
		})
	}
}

// WithHexEncoding allows an optional request to use hex encoding.
func WithHexEncoding(withHexEncoding bool) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.WithHexEncoding = withHexEncoding
			return nil
		})
	}
}
