package roles

import (
	"github.com/hashicorp/watchtower/api"
)

type Option func(*options)

type options struct {
	valueMap                map[string]interface{}
	withScopeId             string
	withAutomaticVersioning bool
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

func WithScopeId(id string) Option {
	return func(o *options) {
		o.withScopeId = id
	}
}

func WithAutomaticVersioning() Option {
	return func(o *options) {
		o.withAutomaticVersioning = true
	}
}

func WithGrantScopeId(inGrantScopeId string) Option {
	return func(o *options) {
		o.valueMap["grant_scope_id"] = inGrantScopeId
	}
}

func DefaultGrantScopeId() Option {
	return func(o *options) {
		o.valueMap["grant_scope_id"] = nil
	}
}

func WithName(inName string) Option {
	return func(o *options) {
		o.valueMap["name"] = inName
	}
}

func DefaultName() Option {
	return func(o *options) {
		o.valueMap["name"] = nil
	}
}

func WithDescription(inDescription string) Option {
	return func(o *options) {
		o.valueMap["description"] = inDescription
	}
}

func DefaultDescription() Option {
	return func(o *options) {
		o.valueMap["description"] = nil
	}
}

func WithDisabled(inDisabled bool) Option {
	return func(o *options) {
		o.valueMap["disabled"] = inDisabled
	}
}

func DefaultDisabled() Option {
	return func(o *options) {
		o.valueMap["disabled"] = nil
	}
}
