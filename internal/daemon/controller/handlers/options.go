// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
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
	WithUserIsAnonymous             bool
	WithOutputFields                *perms.OutputFields
	WithScope                       *scopes.ScopeInfo
	WithPlugin                      *plugins.PluginInfo
	WithAuthorizedActions           []string
	WithAuthorizedCollectionActions map[string]*structpb.ListValue
	WithManagedGroupIds             []string
	WithMemberIds                   []string
	WithHostSetIds                  []string
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

// DEPRECATED: Superceded by WithOutputFields. Will be removed once all handlers
// have been migrated to that.
func WithUserIsAnonymous(anonListing bool) Option {
	return func(o *options) {
		o.WithUserIsAnonymous = anonListing
	}
}

// WithOutputFields provides an option when creating responses to only include
// specific fields
func WithOutputFields(fields *perms.OutputFields) Option {
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

// WithPlugin provides an option when creating responses to include the given
// plugin if allowed
func WithPlugin(plg *plugins.PluginInfo) Option {
	return func(o *options) {
		o.WithPlugin = plg
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

// WithManagedGroupIds provides an option when creating responses to include the given
// managed group IDs if allowed
func WithManagedGroupIds(ids []string) Option {
	return func(o *options) {
		o.WithManagedGroupIds = ids
	}
}

// WithMemberIds provides an option when creating responses to include the given
// member IDs if allowed
func WithMemberIds(ids []string) Option {
	return func(o *options) {
		o.WithMemberIds = ids
	}
}

// WithHostSetIds provides an option when creating responses to include the
// given host set IDs if allowed
func WithHostSetIds(ids []string) Option {
	return func(o *options) {
		o.WithHostSetIds = ids
	}
}
