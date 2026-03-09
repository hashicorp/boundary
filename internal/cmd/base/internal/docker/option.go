// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package docker

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
	withContainerImage string
}

func getDefaultOptions() Options {
	return Options{}
}

// WithContainerImage tells the command which container image
// to start a dev database with
func WithContainerImage(image string) Option {
	return func(o *Options) {
		o.withContainerImage = image
	}
}
