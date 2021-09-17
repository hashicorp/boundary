package proxy

import (
	"github.com/hashicorp/boundary/internal/credential"
)

// Option - how Options are passed as arguments.
type Option func(*Options)

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Options = how options are represented
type Options struct {
	WithEgressCredentials []credential.Credential
}

func getDefaultOptions() Options {
	return Options{
		WithEgressCredentials: nil,
	}
}

// WithEgressCredentials provides an optional egress credentials to use when establishing a proxy
func WithEgressCredentials(creds []credential.Credential) Option {
	return func(o *Options) {
		o.WithEgressCredentials = creds
	}
}
