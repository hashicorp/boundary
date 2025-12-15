// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storagebucketcredential

import "google.golang.org/protobuf/types/known/structpb"

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	WithSecret *structpb.Struct
	WithKeyId  string
}

func getDefaultOptions() options {
	return options{
		WithSecret: nil,
		WithKeyId:  "",
	}
}

// WithSecret provides an optional secret
func WithSecret(s *structpb.Struct) Option {
	return func(o *options) {
		o.WithSecret = s
	}
}

// WithKeyId provides an key id
func WithKeyId(s string) Option {
	return func(o *options) {
		o.WithKeyId = s
	}
}
