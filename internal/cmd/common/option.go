// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package common

// GetOpts - iterate the inbound Options and return a struct.
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

// Option - how Options are passed as arguments.
type Option func(*Options) error

// Options - how Options are represented.
type Options struct {
	WithSkipScopeIdFlag bool
}

func getDefaultOptions() *Options {
	return &Options{}
}

// WithSkipScopeIdFlag tells a command to not create a scope ID flag (usually
// because it's already been defined)
func WithSkipScopeIdFlag(with bool) Option {
	return func(o *Options) error {
		o.WithSkipScopeIdFlag = with
		return nil
	}
}
