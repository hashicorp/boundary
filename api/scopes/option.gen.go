package scopes

import (
	"fmt"

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
	postMap                 map[string]interface{}
	queryMap                map[string]string
	withAutomaticVersioning bool
}

func getDefaultOptions() options {
	return options{
		postMap:  make(map[string]interface{}),
		queryMap: make(map[string]string),
	}
}

func getOpts(opt ...Option) (options, []api.Option) {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	var apiOpts []api.Option
	return opts, apiOpts
}

// If set, and if the version is zero during an update, the API will perform a
// fetch to get the current version of the resource and populate it during the
// update call. This is convenient but opens up the possibility for subtle
// order-of-modification issues, so use carefully.
func WithAutomaticVersioning(enable bool) Option {
	return func(o *options) {
		o.withAutomaticVersioning = enable
	}
}

func WithDescription(inDescription string) Option {
	return func(o *options) {
		o.postMap["description"] = inDescription
	}
}

func DefaultDescription() Option {
	return func(o *options) {
		o.postMap["description"] = nil
	}
}

func WithName(inName string) Option {
	return func(o *options) {
		o.postMap["name"] = inName
	}
}

func DefaultName() Option {
	return func(o *options) {
		o.postMap["name"] = nil
	}
}

func WithSkipAdminRoleCreation(inSkipAdminRoleCreation bool) Option {
	return func(o *options) {
		o.queryMap["skip_admin_role_creation"] = fmt.Sprintf("%v", inSkipAdminRoleCreation)
	}
}

func DefaultSkipAdminRoleCreation() Option {
	return func(o *options) {
		o.postMap["skip_admin_role_creation"] = nil
	}
}

func WithSkipDefaultRoleCreation(inSkipDefaultRoleCreation bool) Option {
	return func(o *options) {
		o.queryMap["skip_default_role_creation"] = fmt.Sprintf("%v", inSkipDefaultRoleCreation)
	}
}

func DefaultSkipDefaultRoleCreation() Option {
	return func(o *options) {
		o.postMap["skip_default_role_creation"] = nil
	}
}
