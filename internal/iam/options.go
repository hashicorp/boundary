package iam

import "io"

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withPublicId                string
	withName                    string
	withDescription             string
	withGroupGrants             bool
	withLimit                   int
	withAutoVivify              bool
	withGrantScopeId            string
	withSkipVetForWrite         bool
	withDisassociate            bool
	withSkipAdminRoleCreation   bool
	withSkipDefaultRoleCreation bool
	withUserId                  string
	withRandomReader            io.Reader
}

func getDefaultOptions() options {
	return options{
		withPublicId:        "",
		withName:            "",
		withDescription:     "",
		withGroupGrants:     false,
		withLimit:           0,
		withAutoVivify:      false,
		withGrantScopeId:    "",
		withSkipVetForWrite: false,
	}
}

// WithGroupGrants provides and option to include group grants
func WithGroupGrants(enable bool) Option {
	return func(o *options) {
		o.withGroupGrants = enable
	}
}

// WithPublicId provides an optional public id
func WithPublicId(id string) Option {
	return func(o *options) {
		o.withPublicId = id
	}
}

// WithDescription provides an optional description
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an option to search by a friendly name
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithAutoVivify provides an option to enable user auto vivification when
// calling repo.LookupUserWithLogin().
func WithAutoVivify(enable bool) Option {
	return func(o *options) {
		o.withAutoVivify = enable
	}
}

// WithGrantScopeId provides an option to specify the scope ID for grants in
// roles.
func WithGrantScopeId(id string) Option {
	return func(o *options) {
		o.withGrantScopeId = id
	}
}

// WithSkipVetForWrite provides an option to allow skipping vet checks to allow
// testing lower-level SQL triggers and constraints
func WithSkipVetForWrite(enable bool) Option {
	return func(o *options) {
		o.withSkipVetForWrite = enable
	}
}

// WithDisassociate provides an option to allow the combining of disassociating
// and associating a user in one operation.
func WithDisassociate(enable bool) Option {
	return func(o *options) {
		o.withDisassociate = enable
	}
}

// WithSkipAdminRoleCreation provides an option to disable the automatic
// creation of an admin role when a new scope is created.
func WithSkipAdminRoleCreation(enable bool) Option {
	return func(o *options) {
		o.withSkipAdminRoleCreation = enable
	}
}

// WithSkipDefaultRoleCreation provides an option to disable the automatic
// creation of a default role when a new scope is created.
func WithSkipDefaultRoleCreation(enable bool) Option {
	return func(o *options) {
		o.withSkipDefaultRoleCreation = enable
	}
}

// WithUserId provides an option to specify the user ID to use when creating roles with new scopes.
func WithUserId(id string) Option {
	return func(o *options) {
		o.withUserId = id
	}
}

// WithRandomReader provides and option to specify a random reader.
func WithRandomReader(reader io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = reader
	}
}
