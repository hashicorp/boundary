// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package listenerutil

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) (*options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}
	return &opts, nil
}

// Option - how Options are passed as arguments
type Option func(*options) error

// options = how options are represented
type options struct {
	withDefaultUiContentSecurityPolicyHeader string
}

func getDefaultOptions() options {
	return options{}
}

// WithDefaultUiContentSecurityPolicyHeader provides a default value for the UI listener's
// Content-Security-Policy header.
func WithDefaultUiContentSecurityPolicyHeader(cspHeader string) Option {
	return func(o *options) error {
		o.withDefaultUiContentSecurityPolicyHeader = cspHeader
		return nil
	}
}
