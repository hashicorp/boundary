// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
// default. When an API call is made options are processed in the order they
// appear in the function call, so for a given argument X, a succession of WithX
// or DefaultX calls will result in the last call taking effect.
type Option func(*options)

type options struct {
	postMap                 map[string]any
	queryMap                map[string]string
	withAutomaticVersioning bool
	withSkipCurlOutput      bool
	withFilter              string
	withListToken           string
	withRecursive           bool
}

func getDefaultOptions() options {
	return options{
		postMap:  make(map[string]any),
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
	if opts.withListToken != "" {
		opts.queryMap["list_token"] = opts.withListToken
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
		o.withSkipCurlOutput = skip
	}
}

// WithListToken tells the API to use the provided list token
// for listing operations on this resource.
func WithListToken(listToken string) Option {
	return func(o *options) {
		o.withListToken = listToken
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
		o.withRecursive = recurse
	}
}

func WithAddress(inAddress string) Option {
	return func(o *options) {
		o.postMap["address"] = inAddress
	}
}

func DefaultAddress() Option {
	return func(o *options) {
		o.postMap["address"] = nil
	}
}

func WithAliases(inAliases []Alias) Option {
	return func(o *options) {
		o.postMap["with_aliases"] = inAliases
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

func WithBrokeredCredentialSourceIds(inBrokeredCredentialSourceIds []string) Option {
	return func(o *options) {
		o.postMap["brokered_credential_source_ids"] = inBrokeredCredentialSourceIds
	}
}

func DefaultBrokeredCredentialSourceIds() Option {
	return func(o *options) {
		o.postMap["brokered_credential_source_ids"] = nil
	}
}

func WithSshTargetDefaultClientPort(inDefaultClientPort uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["default_client_port"] = inDefaultClientPort
		o.postMap["attributes"] = val
	}
}

func DefaultSshTargetDefaultClientPort() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["default_client_port"] = nil
		o.postMap["attributes"] = val
	}
}

func WithTcpTargetDefaultClientPort(inDefaultClientPort uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["default_client_port"] = inDefaultClientPort
		o.postMap["attributes"] = val
	}
}

func DefaultTcpTargetDefaultClientPort() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["default_client_port"] = nil
		o.postMap["attributes"] = val
	}
}

func WithSshTargetDefaultPort(inDefaultPort uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["default_port"] = inDefaultPort
		o.postMap["attributes"] = val
	}
}

func DefaultSshTargetDefaultPort() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["default_port"] = nil
		o.postMap["attributes"] = val
	}
}

func WithTcpTargetDefaultPort(inDefaultPort uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["default_port"] = inDefaultPort
		o.postMap["attributes"] = val
	}
}

func DefaultTcpTargetDefaultPort() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
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

func WithEgressWorkerFilter(inEgressWorkerFilter string) Option {
	return func(o *options) {
		o.postMap["egress_worker_filter"] = inEgressWorkerFilter
	}
}

func DefaultEgressWorkerFilter() Option {
	return func(o *options) {
		o.postMap["egress_worker_filter"] = nil
	}
}

func WithSshTargetEnableSessionRecording(inEnableSessionRecording bool) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["enable_session_recording"] = inEnableSessionRecording
		o.postMap["attributes"] = val
	}
}

func WithHostId(inHostId string) Option {
	return func(o *options) {
		o.postMap["host_id"] = inHostId
	}
}

func WithIngressWorkerFilter(inIngressWorkerFilter string) Option {
	return func(o *options) {
		o.postMap["ingress_worker_filter"] = inIngressWorkerFilter
	}
}

func DefaultIngressWorkerFilter() Option {
	return func(o *options) {
		o.postMap["ingress_worker_filter"] = nil
	}
}

func WithInjectedApplicationCredentialSourceIds(inInjectedApplicationCredentialSourceIds []string) Option {
	return func(o *options) {
		o.postMap["injected_application_credential_source_ids"] = inInjectedApplicationCredentialSourceIds
	}
}

func DefaultInjectedApplicationCredentialSourceIds() Option {
	return func(o *options) {
		o.postMap["injected_application_credential_source_ids"] = nil
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

func WithSshTargetStorageBucketId(inStorageBucketId string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["storage_bucket_id"] = inStorageBucketId
		o.postMap["attributes"] = val
	}
}

func DefaultSshTargetStorageBucketId() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["storage_bucket_id"] = nil
		o.postMap["attributes"] = val
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
