package base

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*Options)

// Options - how Options are represented.
type Options struct {
	withNoTokenScope              bool
	withNoTokenValue              bool
	withSkipDatabaseDestruction   bool
	withSkipAuthMethodCreation    bool
	withSkipScopesCreation        bool
	withSkipHostResourcesCreation bool
	withSkipTargetCreation        bool
}

func getDefaultOptions() Options {
	return Options{}
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

// WithSkipAuthMethodCreation tells the command not to instantiate an auth
// method on first run.
func WithSkipAuthMethodCreation() Option {
	return func(o *Options) {
		o.withSkipAuthMethodCreation = true
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
