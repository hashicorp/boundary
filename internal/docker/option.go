package docker

//GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
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
	WithNoTokenScope bool
	WithNoTokenValue bool

	//WithSkipDatabaseDestruction must be accessible from other packages.
	WithSkipDatabaseDestruction bool

	//WithSkipAuthMethodCreation must be accessible from other packages.
	WithSkipAuthMethodCreation bool

	//WithSkipScopesCreation must be accessible from other packages.
	WithSkipScopesCreation bool

	//WithSkipHostResourcesCreation must be accessible from other packages.
	WithSkipHostResourcesCreation bool

	//WithSkipTargetCreation must be accessible from other packages.
	WithSkipTargetCreation bool

	//WithDatabaseImage must be accessible from other packages.
	WithDatabaseImage string
}

func getDefaultOptions() Options {
	return Options{}
}

// WithNoTokenScope tells the client not to set a scope for the client from a
// saved token's scope, as this can cause confusing behavior at authentication
// time.
func WithNoTokenScope() Option {
	return func(o *Options) {
		o.WithNoTokenScope = true
	}
}

// WithSkipDatabaseDestruction tells the command not to destroy the database even on error.
func WithSkipDatabaseDestruction() Option {
	return func(o *Options) {
		o.WithSkipDatabaseDestruction = true
	}
}

// WithNoTokenValue tells the client not to set a token for the client from a
// saved token's value, as this can cause confusing behavior at authentication
// time.
func WithNoTokenValue() Option {
	return func(o *Options) {
		o.WithNoTokenValue = true
	}
}

// WithSkipAuthMethodCreation tells the command not to instantiate an auth
// method on first run.
func WithSkipAuthMethodCreation() Option {
	return func(o *Options) {
		o.WithSkipAuthMethodCreation = true
	}
}

// WithSkipScopesCreation tells the command not to instantiate scopes on first
// run.
func WithSkipScopesCreation() Option {
	return func(o *Options) {
		o.WithSkipScopesCreation = true
	}
}

// WithSkipHostResourcesCreation tells the command not to instantiate a host
// catalog and related resources on first run.
func WithSkipHostResourcesCreation() Option {
	return func(o *Options) {
		o.WithSkipHostResourcesCreation = true
	}
}

// WithSkipTargetCreation tells the command not to instantiate a target on first
// run.
func WithSkipTargetCreation() Option {
	return func(o *Options) {
		o.WithSkipTargetCreation = true
	}
}

func WithDatabaseImage(image string) Option {
	return func(o *Options) {
		o.WithDatabaseImage = image
	}
}
