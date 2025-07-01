// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package testdirectory

import (
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
)

// Option defines a common functional options type which can be used in a
// variadic parameter pattern.
type Option func(interface{})

// getOpts gets the defaults and applies the opt overrides passed in
func getOpts(t TestingT, opt ...Option) options {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	opts := defaults(t)
	applyOpts(&opts, opt...)
	return opts
}

// applyOpts takes a pointer to the options struct as a set of default options
// and applies the slice of opts as overrides.
func applyOpts(opts interface{}, opt ...Option) {
	for _, o := range opt {
		if o == nil { // ignore any nil Options
			continue
		}
		o(opts)
	}
}

// options are the set of available options for test functions
type options struct {
	withPort                 int
	withHost                 string
	withLogger               hclog.Logger
	withNoTLS                bool
	withMTLS                 bool
	withDisablePanicRecovery bool
	withDefaults             *Defaults

	withMembersOf      []string
	withTokenGroupSIDs [][]byte

	withFirst bool
}

func defaults(t TestingT) options {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	debugLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "testdirectory-default-logger",
		Level: hclog.Error,
	})

	return options{
		withLogger: debugLogger,
		withHost:   "localhost",
		withDefaults: &Defaults{
			UserAttr:  DefaultUserAttr,
			GroupAttr: DefaultGroupAttr,
			UserDN:    DefaultUserDN,
			GroupDN:   DefaultGroupDN,
		},
	}
}

// Defaults define a type for composing all the defaults for Directory.Start(...)
type Defaults struct {
	UserAttr string

	GroupAttr string

	// Users configures the user entries which are empty by default
	Users []*gldap.Entry

	// Groups configures the group entries which are empty by default
	Groups []*gldap.Entry

	// TokenGroups configures the tokenGroup entries which are empty be default
	TokenGroups map[string][]*gldap.Entry

	// UserDN is the base distinguished name to use when searching for users
	// which is "ou=people,dc=example,dc=org" by default
	UserDN string

	// GroupDN is the base distinguished name to use when searching for groups
	// which is "ou=groups,dc=example,dc=org" by default
	GroupDN string

	// AllowAnonymousBind determines if anon binds are allowed
	AllowAnonymousBind bool

	// UPNDomain is the userPrincipalName domain, which enables a
	// userPrincipalDomain login with [username]@UPNDomain (optional)
	UPNDomain string
}

// WithDefaults provides an option to provide a set of defaults to
// Directory.Start(...) which make it much more composable.
func WithDefaults(t TestingT, defaults *Defaults) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			if defaults != nil {
				if defaults.AllowAnonymousBind {
					o.withDefaults.AllowAnonymousBind = true
				}
				if defaults.Users != nil {
					o.withDefaults.Users = defaults.Users
				}
				if defaults.Groups != nil {
					o.withDefaults.Groups = defaults.Groups
				}
				if defaults.UserDN != "" {
					o.withDefaults.UserDN = defaults.UserDN
				}
				if defaults.GroupDN != "" {
					o.withDefaults.GroupDN = defaults.GroupDN
				}
				if len(defaults.TokenGroups) > 0 {
					o.withDefaults.TokenGroups = defaults.TokenGroups
				}
				if defaults.UserAttr != "" {
					o.withDefaults.UserAttr = defaults.UserAttr
				}
				if defaults.GroupAttr != "" {
					o.withDefaults.GroupAttr = defaults.GroupAttr
				}
				if defaults.UPNDomain != "" {
					o.withDefaults.UPNDomain = defaults.UPNDomain
				}
			}
		}
	}
}

// WithMTLS provides the option to use mTLS for the directory.
func WithMTLS(t TestingT) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withMTLS = true
		}
	}
}

// WithNoTLS provides the option to not use TLS for the directory.
func WithNoTLS(t TestingT) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withNoTLS = true
		}
	}
}

// WithLogger provides the optional logger for the directory.
func WithLogger(t TestingT, l hclog.Logger) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withLogger = l
		}
	}
}

// WithPort provides an optional port for the directory. 0 causes a
// started server with a random port. Any other value returns a started server
// on that port.
func WithPort(t TestingT, port int) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withPort = port
		}
	}
}

// WithHost provides an optional hostname for the directory
func WithHost(t TestingT, host string) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withHost = strings.TrimSpace(host)
		}
	}
}

// withFirst provides the option to only find the first match.
func withFirst(t TestingT) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withFirst = true
		}
	}
}

// WithMembersOf specifies optional memberOf attributes for user
// entries
func WithMembersOf(t TestingT, membersOf ...string) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withMembersOf = membersOf
		}
	}
}

// WithTokenGroups specifies optional test tokenGroups SID attributes for user
// entries
func WithTokenGroups(t TestingT, tokenGroupSID ...[]byte) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withTokenGroupSIDs = tokenGroupSID
		}
	}
}

func WithDisablePanicRecovery(t TestingT, disable bool) Option {
	return func(o interface{}) {
		if o, ok := o.(*options); ok {
			o.withDisablePanicRecovery = disable
		}
	}
}
