// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package dbtest

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*Options)

// Options - how Options are represented.
type Options struct {
	withTemplate string
}

func getDefaultOptions() Options {
	return Options{}
}

// WithTemplate tells the command with database template to use
// when creating a new test database.
func WithTemplate(template string) Option {
	return func(o *Options) {
		o.withTemplate = template
	}
}
