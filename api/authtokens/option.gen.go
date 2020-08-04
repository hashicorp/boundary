package authtokens

import (
	"github.com/hashicorp/watchtower/api"
)

type Option func(*options)

type options struct {
	valueMap    map[string]interface{}
	withScopeId string
}

func getDefaultOptions() options {
	return options{
		valueMap: make(map[string]interface{}),
	}
}

func getOpts(opt ...Option) (options, []api.Option) {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	var apiOpts []api.Option
	if opts.withScopeId != "" {
		apiOpts = append(apiOpts, api.WithScopeId(opts.withScopeId))
	}
	return opts, apiOpts
}

func DefaultScopeId() Option {
	return func(o *options) {
		o.withScopeId = ""
	}
}

func WithScopeId(id string) Option {
	return func(o *options) {
		o.withScopeId = id
	}
}
