package proxy

import (
	serverpb "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
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
	WithEgressCredentials []*serverpb.Credential
}

func getDefaultOptions() Options {
	return Options{
		WithEgressCredentials: nil,
	}
}

// WithEgressCredentials provides an optional egress credentials to use when establishing a proxy
func WithEgressCredentials(creds []*serverpb.Credential) Option {
	return func(o *Options) {
		o.WithEgressCredentials = creds
	}
}
