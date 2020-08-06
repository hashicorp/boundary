package authmethods

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

func WithPasswordAuthMethodMinUserNameLength(inMinUserNameLength uint32) Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_user_name_length"] = inMinUserNameLength
		o.valueMap["attributes"] = val
	}
}

func DefaultPasswordAuthMethodMinUserNameLength() Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["min_user_name_length"] = nil
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

func WithType(inType string) Option {
	return func(o *options) {
		o.valueMap["type"] = inType
	}
}

func DefaultType() Option {
	return func(o *options) {
		o.valueMap["type"] = nil
	}
}

func WithPasswordAccountUsername(inUsername string) Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["username"] = inUsername
		o.valueMap["attributes"] = val
	}
}

func DefaultPasswordAccountUsername() Option {
	return func(o *options) {
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["username"] = nil
		o.valueMap["attributes"] = val
	}
}
