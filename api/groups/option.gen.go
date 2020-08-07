package groups

import (
	"github.com/hashicorp/watchtower/api"
)

// Option is a func that sets optional attributes for a call. This does not need
// to be used directly, but instead option arguments are built from the
// functions in this package. WithX options set a value to that given in the
// argument; DefaultX options indicate that the value should be set to its
// default. When an API call is made, options are processed in-order, so for a
// given argument X, a succession of WithX or DefaultX calls will result in the
// last call taking effect.
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

// If set, and if the version is zero during an update, the API will perform a
// fetch to get the current version of the resource and populate it during the
// update call. This is convenient but opens up the possibility for subtle
// order-of-modification issues, so use carefully.
func WithAutomaticVersioning() Option {
	return func(o *options) {
		o.withAutomaticVersioning = true
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
