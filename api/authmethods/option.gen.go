package authmethods

import (
	"github.com/hashicorp/boundary/api"
)

// Option is a func that sets optional attributes for a call. This does not need
// to be used directly, but instead option arguments are built from the
// functions in this package. WithX options set a value to that given in the
// argument; DefaultX options indicate that the value should be set to its
// default. When an API call is made options are processed in ther order they
// appear in the function call, so for a given argument X, a succession of WithX
// or DefaultX calls will result in the last call taking effect.
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

func WithAttributes(inAttributes map[string]interface{}) Option {
	return func(o *options) {
		o.valueMap["attributes"] = inAttributes
	}
}

func DefaultAttributes() Option {
	return func(o *options) {
		o.valueMap["attributes"] = nil
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

func WithPasswordAccountLoginName(inLoginName string) Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["login_name"] = inLoginName
		o.valueMap["attributes"] = val
	}
}

func DefaultPasswordAccountLoginName() Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["login_name"] = nil
		o.valueMap["attributes"] = val
	}
}

func WithPasswordAuthMethodMinLoginNameLength(inMinLoginNameLength uint32) Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_login_name_length"] = inMinLoginNameLength
		o.valueMap["attributes"] = val
	}
}

func DefaultPasswordAuthMethodMinLoginNameLength() Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_login_name_length"] = nil
		o.valueMap["attributes"] = val
	}
}

func WithPasswordAuthMethodMinPasswordLength(inMinPasswordLength uint32) Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_password_length"] = inMinPasswordLength
		o.valueMap["attributes"] = val
	}
}

func DefaultPasswordAuthMethodMinPasswordLength() Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_password_length"] = nil
		o.valueMap["attributes"] = val
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

func WithPasswordAccountPassword(inPassword string) Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["password"] = inPassword
		o.valueMap["attributes"] = val
	}
}

func DefaultPasswordAccountPassword() Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["password"] = nil
		o.valueMap["attributes"] = val
	}
}
