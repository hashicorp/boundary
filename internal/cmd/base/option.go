// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*Options)

// Options - how Options are represented.
type Options struct {
	withNoTokenScope                        bool
	withNoTokenValue                        bool
	withSkipDefaultRoleCreation             bool
	withSkipDatabaseDestruction             bool
	withSkipAuthMethodCreation              bool
	withSkipOidcAuthMethodCreation          bool
	withSkipLdapAuthMethodCreation          bool
	withSkipScopesCreation                  bool
	withSkipHostResourcesCreation           bool
	withSkipTargetCreation                  bool
	withContainerImage                      string
	withDialect                             string
	withDatabaseTemplate                    string
	withEventerConfig                       *event.EventerConfig
	withEventFlags                          *EventFlags
	withEventWrapper                        wrapping.Wrapper
	withAttributeFieldPrefix                string
	withStatusCode                          int
	withHostPlugin                          func() (string, plugin.HostPluginServiceClient)
	withEventGating                         bool
	withImplicitId                          string
	WithSkipScopeIdFlag                     bool
	WithInterceptedToken                    *string
	withAuthUserTargetAuthorizeSessionGrant bool
	withIamOptions                          []iam.Option
}

func getDefaultOptions() Options {
	return Options{
		withContainerImage: "postgres",
		withDialect:        "postgres",
	}
}

// WithNoTokenScope tells the client not to set a scope for the client from a
// saved token's scope, as this can cause confusing behavior at authentication
// time.
func WithNoTokenScope() Option {
	return func(o *Options) {
		o.withNoTokenScope = true
	}
}

// WithSkipDatabaseDestruction tells the command not to destroy the database even on error.
func WithSkipDatabaseDestruction() Option {
	return func(o *Options) {
		o.withSkipDatabaseDestruction = true
	}
}

// WithNoTokenValue tells the client not to set a token for the client from a
// saved token's value, as this can cause confusing behavior at authentication
// time.
func WithNoTokenValue() Option {
	return func(o *Options) {
		o.withNoTokenValue = true
	}
}

// WithSkipDefaultRoleCreation tells the command not to instantiate the default
// global role
func WithSkipDefaultRoleCreation() Option {
	return func(o *Options) {
		o.withSkipDefaultRoleCreation = true
	}
}

// WithSkipAuthMethodCreation tells the command not to instantiate any auth
// method on first run.
func WithSkipAuthMethodCreation() Option {
	return func(o *Options) {
		o.withSkipAuthMethodCreation = true
	}
}

// WithSkipOidcAuthMethodCreation tells the command not to instantiate an OIDC auth
// method on first run, useful in some tests.
func WithSkipOidcAuthMethodCreation() Option {
	return func(o *Options) {
		o.withSkipOidcAuthMethodCreation = true
	}
}

// WithSkipLdapAuthMethodCreation tells the command not to instantiate an LDAP auth
// method on first run, useful in some tests.
func WithSkipLdapAuthMethodCreation() Option {
	return func(o *Options) {
		o.withSkipLdapAuthMethodCreation = true
	}
}

// WithSkipScopesCreation tells the command not to instantiate scopes on first
// run.
func WithSkipScopesCreation() Option {
	return func(o *Options) {
		o.withSkipScopesCreation = true
	}
}

// WithSkipHostResourcesCreation tells the command not to instantiate a host
// catalog and related resources on first run.
func WithSkipHostResourcesCreation() Option {
	return func(o *Options) {
		o.withSkipHostResourcesCreation = true
	}
}

// WithSkipTargetCreation tells the command not to instantiate a target on first
// run.
func WithSkipTargetCreation() Option {
	return func(o *Options) {
		o.withSkipTargetCreation = true
	}
}

// WithContainerImage tells the command which container image
// to start a dev database with
func WithContainerImage(name string) Option {
	return func(o *Options) {
		o.withContainerImage = name
	}
}

func withDialect(dialect string) Option {
	return func(o *Options) {
		o.withDialect = dialect
	}
}

// WithEventer allows an optional eventer config
func WithEventerConfig(config *event.EventerConfig) Option {
	return func(o *Options) {
		o.withEventerConfig = config
	}
}

// WithEventer allows an optional event configuration flags which override
// whatever is in the EventerConfig
func WithEventFlags(flags *EventFlags) Option {
	return func(o *Options) {
		o.withEventFlags = flags
	}
}

func WithEventAuditWrapper(w wrapping.Wrapper) Option {
	return func(o *Options) {
		o.withEventWrapper = w
	}
}

// WithAttributeFieldPrefix tells the command what prefix
// to attach to attribute fields when they are returned as errors.
func WithAttributeFieldPrefix(p string) Option {
	return func(o *Options) {
		o.withAttributeFieldPrefix = p
	}
}

// WithStatusCode allows passing status codes to functions
func WithStatusCode(statusCode int) Option {
	return func(o *Options) {
		o.withStatusCode = statusCode
	}
}

// WithDatabaseTemplate allows for using an existing database template for
// initializing the boundary database.
func WithDatabaseTemplate(template string) Option {
	return func(o *Options) {
		o.withDatabaseTemplate = template
	}
}

// WithHostPlugin allows specifying a plugin ID and implementation to create at
// startup
func WithHostPlugin(pluginId string, plg plugin.HostPluginServiceClient) Option {
	return func(o *Options) {
		o.withHostPlugin = func() (string, plugin.HostPluginServiceClient) {
			return pluginId, plg
		}
	}
}

// WithEventGating starts the eventer in gated mode
func WithEventGating(with bool) Option {
	return func(o *Options) {
		o.withEventGating = with
	}
}

// WithImplicitId is used when creating the command if we are implicitly
// overriding the ID via a top-level read/update/delete command
func WithImplicitId(with string) Option {
	return func(o *Options) {
		o.withImplicitId = with
	}
}

// WithSkipScopeIdFlag tells a command to not create a scope ID flag (usually
// because it's already been defined)
func WithSkipScopeIdFlag(with bool) Option {
	return func(o *Options) {
		o.WithSkipScopeIdFlag = with
	}
}

// WithInterceptedToken provides a string pointer that will have the token
// assigned to it when performing an authenticate command.
func WithInterceptedToken(s *string) Option {
	return func(o *Options) {
		o.WithInterceptedToken = s
	}
}

// WithAuthUserTargetAuthorizeSessionGrant indicates that we should add an
// authorize-session grant to the global authenticated user role. This is the
// default for dev mode.
func WithAuthUserTargetAuthorizeSessionGrant(with bool) Option {
	return func(o *Options) {
		o.withAuthUserTargetAuthorizeSessionGrant = with
	}
}

// WithIamOptions provides options to pass through to the IAM package when
// creating initial resources
func WithIamOptions(with ...iam.Option) Option {
	return func(o *Options) {
		o.withIamOptions = with
	}
}
