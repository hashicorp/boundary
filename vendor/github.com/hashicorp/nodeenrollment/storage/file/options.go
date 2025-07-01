// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package file

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...Option) (*Options, error) {
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

type Options struct {
	withBaseDirectory string
	withSkipCleanup   bool
}

// Option is a function that takes in an options struct and sets values or
// returns an error
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{}
}

// WithDirectory allows specifying a base directory to use
func WithBaseDirectory(with string) Option {
	return func(o *Options) error {
		o.withBaseDirectory = with
		return nil
	}
}

// WithSkipCleanup causes FileStorage cleanup to be a no-op, useful for
// inspecting state after the fact
func WithSkipCleanup(with bool) Option {
	return func(o *Options) error {
		o.withSkipCleanup = with
		return nil
	}
}
