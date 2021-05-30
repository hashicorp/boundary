package node

import (
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withWrapper wrapping.Wrapper
	withSalt    []byte
	withInfo    []byte
}

func getDefaultOptions() options {
	return options{}
}

func WithWrapper(wrapper wrapping.Wrapper) Option {
	return func(o *options) {
		o.withWrapper = wrapper
	}
}

func WithSalt(salt []byte) Option {
	return func(o *options) {
		o.withSalt = salt
	}
}

func WithInfo(info []byte) Option {
	return func(o *options) {
		o.withInfo = info
	}
}
