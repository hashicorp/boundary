package targets

import (
	"strconv"
	"strings"

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
	withSkipCurlOutput      bool
	withFilter              string
	withRecursive           bool
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
		if o != nil {
			o(&opts)
		}
	}
	var apiOpts []api.Option
	if opts.withSkipCurlOutput {
		apiOpts = append(apiOpts, api.WithSkipCurlOutput(true))
	}
	if opts.withFilter != "" {
		opts.queryMap["filter"] = opts.withFilter
	}
	if opts.withRecursive {
		opts.queryMap["recursive"] = strconv.FormatBool(opts.withRecursive)
	}
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

// WithSkipCurlOutput tells the API to not use the current call for cURL output.
// Useful for when we need to look up versions.
func WithSkipCurlOutput(skip bool) Option {
	return func(o *options) {
		o.withSkipCurlOutput = true
	}
}

// WithFilter tells the API to filter the items returned using the provided
// filter term.  The filter should be in a format supported by
// hashicorp/go-bexpr.
func WithFilter(filter string) Option {
	return func(o *options) {
		o.withFilter = strings.TrimSpace(filter)
	}
}

// WithRecursive tells the API to use recursion for listing operations on this
// resource
func WithRecursive(recurse bool) Option {
	return func(o *options) {
		o.withRecursive = true
	}
}

func WithApplicationCredentialLibraryIds(inApplicationCredentialLibraryIds []string) Option {
	return func(o *options) {
		o.postMap["application_credential_library_ids"] = inApplicationCredentialLibraryIds
	}
}

func DefaultApplicationCredentialLibraryIds() Option {
	return func(o *options) {
		o.postMap["application_credential_library_ids"] = nil
	}
}

func WithApplicationCredentialSourceIds(inApplicationCredentialSourceIds []string) Option {
	return func(o *options) {
		o.postMap["application_credential_source_ids"] = inApplicationCredentialSourceIds
	}
}

func DefaultApplicationCredentialSourceIds() Option {
	return func(o *options) {
		o.postMap["application_credential_source_ids"] = nil
	}
}

func WithAttributes(inAttributes map[string]interface{}) Option {
	return func(o *options) {
		o.postMap["attributes"] = inAttributes
	}
}

func DefaultAttributes() Option {
	return func(o *options) {
		o.postMap["attributes"] = nil
	}
}

func WithTcpTargetDefaultPort(inDefaultPort uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["default_port"] = inDefaultPort
		o.postMap["attributes"] = val
	}
}

func DefaultTcpTargetDefaultPort() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["default_port"] = nil
		o.postMap["attributes"] = val
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

func WithEgressCredentialSourceIds(inEgressCredentialSourceIds []string) Option {
	return func(o *options) {
		o.postMap["egress_credential_source_ids"] = inEgressCredentialSourceIds
	}
}

func DefaultEgressCredentialSourceIds() Option {
	return func(o *options) {
		o.postMap["egress_credential_source_ids"] = nil
	}
}

func WithHostId(inHostId string) Option {
	return func(o *options) {
		o.postMap["host_id"] = inHostId
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

func WithScopeId(inScopeId string) Option {
	return func(o *options) {
		o.postMap["scope_id"] = inScopeId
	}
}

func WithScopeName(inScopeName string) Option {
	return func(o *options) {
		o.postMap["scope_name"] = inScopeName
	}
}

func WithSessionConnectionLimit(inSessionConnectionLimit int32) Option {
	return func(o *options) {
		o.postMap["session_connection_limit"] = inSessionConnectionLimit
	}
}

func DefaultSessionConnectionLimit() Option {
	return func(o *options) {
		o.postMap["session_connection_limit"] = nil
	}
}

func WithSessionMaxSeconds(inSessionMaxSeconds uint32) Option {
	return func(o *options) {
		o.postMap["session_max_seconds"] = inSessionMaxSeconds
	}
}

func DefaultSessionMaxSeconds() Option {
	return func(o *options) {
		o.postMap["session_max_seconds"] = nil
	}
}

func WithWorkerFilter(inWorkerFilter string) Option {
	return func(o *options) {
		o.postMap["worker_filter"] = inWorkerFilter
	}
}

func DefaultWorkerFilter() Option {
	return func(o *options) {
		o.postMap["worker_filter"] = nil
	}
}
