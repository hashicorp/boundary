package node

import (
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// option - how Options are passed as arguments.
type option func(*options)

// options = how options are represented
type options struct {
	withWrapper wrapping.Wrapper
	withSalt    []byte
	withInfo    []byte
}

func getDefaultOptions() options {
	return options{}
}

func withWrapper(wrapper wrapping.Wrapper) option {
	return func(o *options) {
		o.withWrapper = wrapper
	}
}

func withSalt(salt []byte) option {
	return func(o *options) {
		o.withSalt = salt
	}
}

func withInfo(info []byte) option {
	return func(o *options) {
		o.withInfo = info
	}
}
