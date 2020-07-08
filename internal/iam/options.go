package iam

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
	withPublicId        string
	withName            string
	withScope           *Scope
	withDescription     string
	withParentId        *string
	withLimit           int
	withAutoVivify      bool
	withSkipVetForWrite bool
}

func getDefaultOptions() options {
	return options{
		withPublicId:        "",
		withScope:           nil,
		withDescription:     "",
		withName:            "",
		withParentId:        nil,
		withLimit:           0,
		withAutoVivify:      false,
		withSkipVetForWrite: false,
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

// withScope provides an optional scope and used within the package
func withScope(s *Scope) Option {
	return func(o *options) {
		o.withScope = s
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

// WithSkipVetForWrite provides an option to allow skipping vet checks to allow
// testing lower-level SQL triggers and constraints
func WithSkipVetForWrite(enable bool) Option {
	return func(o *options) {
		o.withSkipVetForWrite = enable
	}
}
