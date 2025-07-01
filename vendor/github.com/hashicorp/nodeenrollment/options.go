// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nodeenrollment

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/types/known/structpb"
)

// GetOpts iterates the inbound Options and returns a struct and any errors
func GetOpts(opt ...Option) (*Options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(opts); err != nil {
			return nil, err
		}

	}
	return opts, nil
}

// Options contains various options. The values are exported since the options
// are parsed in various other packages.
type Options struct {
	WithCertificateLifetime                               time.Duration
	WithNotBeforeClockSkew                                time.Duration
	WithNotAfterClockSkew                                 time.Duration
	WithRandomReader                                      io.Reader
	WithNonce                                             string
	WithTlsVerifyOptionsFunc                              func(*x509.CertPool) x509.VerifyOptions
	WithStorageWrapper                                    wrapping.Wrapper
	WithRegistrationWrapper                               wrapping.Wrapper
	WithSkipStorage                                       bool
	WithExpectedPublicKey                                 []byte
	WithState                                             *structpb.Struct
	WithWrappingRegistrationFlowApplicationSpecificParams *structpb.Struct
	WithAlpnProtoPrefix                                   string
	WithServerName                                        string
	WithExtraAlpnProtos                                   []string
	WithReinitializeRoots                                 bool
	WithActivationToken                                   string
	WithMaximumServerLedActivationTokenLifetime           time.Duration
	WithNativeConns                                       bool
	WithLogger                                            hclog.Logger
	WithTestErrorContains                                 string
}

// Option is a function that takes in an options struct and sets values or
// returns an error
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{
		WithCertificateLifetime:                     DefaultCertificateLifetime,
		WithNotBeforeClockSkew:                      DefaultNotBeforeClockSkewDuration,
		WithNotAfterClockSkew:                       DefaultNotAfterClockSkewDuration,
		WithMaximumServerLedActivationTokenLifetime: DefaultMaximumServerLedActivationTokenLifetime,
		WithRandomReader:                            rand.Reader,
		WithLogger:                                  hclog.NewNullLogger(),
	}
}

// WithCertificateLifetime allows overriding a default duration for certificate
// creation. If 0 is passed in, the default will be used; to get an actual zero
// lifetime (e.g. to only use skew), just specify something short, like a
// nanosecond.
func WithCertificateLifetime(with time.Duration) Option {
	return func(o *Options) error {
		if with == 0 {
			o.WithCertificateLifetime = DefaultCertificateLifetime
			return nil
		}
		o.WithCertificateLifetime = with
		return nil
	}
}

// WithNotBeforeClockSkew allows overriding a default duration for certificate
// NotBefore clock skew handling
func WithNotBeforeClockSkew(with time.Duration) Option {
	return func(o *Options) error {
		o.WithNotBeforeClockSkew = with
		return nil
	}
}

// WithNotAfterClockSkew allows overriding a default duration for certificate
// NotAfter clock skew handling
func WithNotAfterClockSkew(with time.Duration) Option {
	return func(o *Options) error {
		o.WithNotAfterClockSkew = with
		return nil
	}
}

// WithRandomReader allows specifying a reader to use in place of the default
// (crypto/rand.Reader)
func WithRandomReader(with io.Reader) Option {
	return func(o *Options) error {
		o.WithRandomReader = with
		return nil
	}
}

// WithNonce is used at various points for encoding nonces in certs or expecting
// them there
func WithNonce(with string) Option {
	return func(o *Options) error {
		o.WithNonce = with
		return nil
	}
}

// WithTlsVerifyOptionsFunc allows specifying a custom TLS certificate
// VerifyFunc, useful for testing
func WithTlsVerifyOptionsFunc(with func(*x509.CertPool) x509.VerifyOptions) Option {
	return func(o *Options) error {
		o.WithTlsVerifyOptionsFunc = with
		return nil
	}
}

// WithStorageWrapper will cause the library to wrap any sensitive information
// (private keys, nonces, etc.) with the given wrapper prior to writing to
// storage, and to unwrap when reading from storage
func WithStorageWrapper(with wrapping.Wrapper) Option {
	return func(o *Options) error {
		o.WithStorageWrapper = with
		return nil
	}
}

// WithRegistrationWrapper can be used when fetching node credentials to provide
// registration information. If you want to support more than one, use a pooled
// wrapper
// (https://pkg.go.dev/github.com/hashicorp/go-kms-wrapping/v2/extras/multi)
func WithRegistrationWrapper(with wrapping.Wrapper) Option {
	return func(o *Options) error {
		o.WithRegistrationWrapper = with
		return nil
	}
}

// WithSkipStorage allows indicating that the newly generated resource should
// not be stored in storage, but simply returned in-memory only, useful for
// tests or cases where the storage implementation wants to manage storage
// lifecycle (e.g. with transactions)
func WithSkipStorage(with bool) Option {
	return func(o *Options) error {
		o.WithSkipStorage = with
		return nil
	}
}

// WithExpectedPublicKey allows indicating a public key that we expect to be the
// key signed by a certificate
func WithExpectedPublicKey(with []byte) Option {
	return func(o *Options) error {
		o.WithExpectedPublicKey = with
		return nil
	}
}

// WithState allows passing state in to some registration functions to round
// trip to NodeInformation storage
func WithState(with *structpb.Struct) Option {
	return func(o *Options) error {
		o.WithState = with
		return nil
	}
}

// WithWrappingRegistrationFlowApplicationSpecificParams allows passing extra application
// specific parameters when using the wrapping registration flow
func WithWrappingRegistrationFlowApplicationSpecificParams(with *structpb.Struct) Option {
	return func(o *Options) error {
		o.WithWrappingRegistrationFlowApplicationSpecificParams = with
		return nil
	}
}

// WithAlpnProtoPrefix is used to convey information about which proto is being used
// to handle a connection
func WithAlpnProtoPrefix(with string) Option {
	const op = "nodeenrollment.WithAlpnProtoPrefix"
	return func(o *Options) error {
		switch with {
		case FetchNodeCredsNextProtoV1Prefix, AuthenticateNodeNextProtoV1Prefix, CertificatePreferenceV1Prefix:
			o.WithAlpnProtoPrefix = with
			return nil
		default:
			return fmt.Errorf("(%s) unknown proto prefix %s", op, with)
		}
	}
}

// WithServerName is used to pass a server name to include in a TLS config
func WithServerName(with string) Option {
	return func(o *Options) error {
		o.WithServerName = with
		return nil
	}
}

// WithExtraAlpnProtos is used to allow passing additional ALPN protos in via a
// ClientHello message, e.g. via the Dial function in the protocol package. This
// can allow users of the library to perform an extra switch on the desired
// protocol post-authentication.
func WithExtraAlpnProtos(with []string) Option {
	return func(o *Options) error {
		o.WithExtraAlpnProtos = with
		return nil
	}
}

// WithReinitializeRoots, if set to true, indicates that the existing roots should be
// removed entirely before rotation
func WithReinitializeRoots(with bool) Option {
	return func(o *Options) error {
		o.WithReinitializeRoots = with
		return nil
	}
}

// WithActivationToken is used to pass an activation token; typically this will
// be to pass a server-generated activation token as the nonce for a request
func WithActivationToken(with string) Option {
	return func(o *Options) error {
		o.WithActivationToken = with
		return nil
	}
}

// WithMaximumActivationTokenLifetime allows overriding a default duration for
// server-led activation token lifetime
func WithMaximumServerLedActivationTokenLifetime(with time.Duration) Option {
	return func(o *Options) error {
		o.WithMaximumServerLedActivationTokenLifetime = with
		return nil
	}
}

// WithNativeConns, if set to true, indicates to use the native protocol package
// conn type to return from the split listener listeners
func WithNativeConns(with bool) Option {
	return func(o *Options) error {
		o.WithNativeConns = with
		return nil
	}
}

// WithLogger allows passing in a logger to use for debugging purposes
func WithLogger(with hclog.Logger) Option {
	return func(o *Options) error {
		o.WithLogger = with
		return nil
	}
}

// WithTestErrorContains is used in some tests to pass expected error values
func WithTestErrorContains(with string) Option {
	return func(o *Options) error {
		o.WithTestErrorContains = with
		return nil
	}
}
