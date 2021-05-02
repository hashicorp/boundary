package handlers

import (
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/structpb"
)

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments. Some of these are used for
// types within the handlers package, and some are for handlers to re-use across
// the various handler types.
type Option func(*options)

// options = how options are represented
type options struct {
	withDiscardUnknownFields        bool
	WithLogger                      hclog.Logger
	WithUserIsAnonymous             bool
	WithOutputFields                *perms.OutputFieldsMap
	WithScope                       *scopes.ScopeInfo
	WithAuthorizedActions           []string
	WithAuthorizedCollectionActions map[string]*structpb.ListValue
}

func getDefaultOptions() options {
	return options{}
}

// WithDiscardUnknownFields provides an option to cause StructToProto to ignore
// unknown fields. This is useful in some instances when we need to unmarshal a
// value from a pb.Struct after we've added some custom extra fields.
func WithDiscardUnknownFields(discard bool) Option {
	return func(o *options) {
		o.withDiscardUnknownFields = discard
	}
}

// WithLogger provides an option include a logger
func WithLogger(logger hclog.Logger) Option {
	return func(o *options) {
		o.WithLogger = logger
	}
}

// DEPRECATED: Superceded by WithOutputFields. Will be removed once all handlers
// have been migrated to that.
func WithUserIsAnonymous(anonListing bool) Option {
	return func(o *options) {
		o.WithUserIsAnonymous = anonListing
	}
}

// WithOutputFields provides an option when creating responses to only include
// specific fields
func WithOutputFields(fields *perms.OutputFieldsMap) Option {
	return func(o *options) {
		o.WithOutputFields = fields
	}
}

// WithScope provides an option when creating responses to include the given
// scope if allowed
func WithScope(scp *scopes.ScopeInfo) Option {
	return func(o *options) {
		o.WithScope = scp
	}
}

// WithAuthorizedActions provides an option when creating responses to include the given
// authorized actions if allowed
func WithAuthorizedActions(acts []string) Option {
	return func(o *options) {
		o.WithAuthorizedActions = acts
	}
}

// WithAuthorizedCollectionActions provides an option when creating responses to include the given
// authorized collection actions if allowed
func WithAuthorizedCollectionActions(colActs map[string]*structpb.ListValue) Option {
	return func(o *options) {
		o.WithAuthorizedCollectionActions = colActs
	}
}
