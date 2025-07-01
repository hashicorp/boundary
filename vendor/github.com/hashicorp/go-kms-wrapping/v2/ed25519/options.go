// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ed25519

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const (
	ConfigPrivKey     = "priv_key"
	ConfigPubKey      = "pub_key"
	ConfigKeyId       = "key_id"
	ConfigKeyPurposes = "key_purposes"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	const op = "ed25519.getOpts"
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case ConfigKeyId:
				opts.WithKeyId = v
			case ConfigKeyPurposes:
				opts.WithKeyPurposes = []wrapping.KeyPurpose{} // start with an empty list
				for _, raw := range strings.Split(v, ",") {
					p, ok := wrapping.KeyPurpose_value[strings.TrimSpace(raw)]
					if !ok {
						return nil, fmt.Errorf("%s: invalid key purpose %q: %w", op, raw, wrapping.ErrInvalidParameter)
					}
					opts.WithKeyPurposes = append(opts.WithKeyPurposes, wrapping.KeyPurpose(p))
				}
			case ConfigPubKey:
				// PKIX, ASN.1 DER form
				blk, _ := pem.Decode([]byte(v))
				if blk == nil || blk.Bytes == nil {
					return nil, fmt.Errorf("%s: unable to parse %s PEM", op, ConfigPubKey)
				}
				anyKey, err := x509.ParsePKIXPublicKey(blk.Bytes)
				if err != nil {
					return nil, fmt.Errorf("%s: %s is not a valid public key in PKIX, ASN.1 DER form", op, ConfigPubKey)
				}
				var ok bool
				opts.WithPubKey, ok = anyKey.(ed25519.PublicKey)
				if !ok {
					return nil, fmt.Errorf("%s: %s is not a ed25519 public key", op, ConfigPubKey)
				}
			case ConfigPrivKey:
				// PKCS #8, ASN.1 DER form
				blk, _ := pem.Decode([]byte(v))
				if blk == nil || blk.Bytes == nil {
					return nil, fmt.Errorf("%s: unable to parse %s PEM", op, ConfigPrivKey)
				}
				anyKey, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
				if err != nil {
					return nil, fmt.Errorf("%s: %s is not a valid private key in PKCS #8, ASN.1 DER form", op, ConfigPrivKey)
				}
				var ok bool
				opts.WithPrivKey, ok = anyKey.(ed25519.PrivateKey)
				if !ok {
					return nil, fmt.Errorf("%s: %s is not a ed25519 private key", op, ConfigPrivKey)
				}
			}
		}
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
		}
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options

	WithPrivKey ed25519.PrivateKey
	WithPubKey  ed25519.PublicKey
}

func getDefaultOptions() options {
	return options{}
}

// WithPrivKey provides a common way to pass in a private key.  This local
// option will override a ConfigMap provide option.
func WithPrivKey(k ed25519.PrivateKey) wrapping.Option {
	const op = "ed25519.WithPrivKey"
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			switch {
			case len(k) != ed25519.PrivateKeySize:
				return fmt.Errorf("%s: expected private key with %d bytes and got %d: %w", op, ed25519.PrivateKeySize, len(k), wrapping.ErrInvalidParameter)
			}
			o.WithPrivKey = k
			return nil
		})
	}
}

// WithPubKey provides a common way to pass in a public key. This local
// option will override a ConfigMap provide option.
func WithPubKey(k ed25519.PublicKey) wrapping.Option {
	const op = "ed25519.WithPublicKey"
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			switch {
			case len(k) != ed25519.PublicKeySize:
				return fmt.Errorf("%s: expected public key with %d bytes and got %d: %w", op, ed25519.PublicKeySize, len(k), wrapping.ErrInvalidParameter)
			}
			o.WithPubKey = k
			return nil
		})
	}
}
