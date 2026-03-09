// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package client

// GetOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			err := o(&opts)
			if err != nil {
				return opts, err
			}
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments.
type Option func(*options) error

// options - how options are represented.
type options struct {
	withOutputCurlString bool
}

func getDefaultOptions() options {
	return options{}
}

// WithOutputCurlString specifies that the client should return an
// OutputStringError that prints out the curl string for the request being generated.
func WithOutputCurlString() Option {
	return func(o *options) error {
		o.withOutputCurlString = true
		return nil
	}
}
