package password

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withName              string
	withDescription       string
	WithLoginName         string
	withLimit             int
	withConfig            Configuration
	withPublicId          string
	password              string
	withPassword          bool
	withOrderByCreateTime bool
	ascending             bool
}

func getDefaultOptions() options {
	return options{
		withConfig: NewArgon2Configuration(),
	}
}

// WithPublicId provides an optional public id
func WithPublicId(id string) Option {
	return func(o *options) {
		o.withPublicId = id
	}
}

// WithDescription provides an optional description.
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an optional name.
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithLoginName provides an optional login name.
func WithLoginName(loginName string) Option {
	return func(o *options) {
		o.WithLoginName = loginName
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}

// WithPassword provides an optional password.
func WithPassword(password string) Option {
	return func(o *options) {
		o.password = password
		o.withPassword = true
	}
}

// WithConfiguration provides an optional configuration.
func WithConfiguration(config Configuration) Option {
	return func(o *options) {
		o.withConfig = config
	}
}

// WithOrderByCreateTime provides an option to specify ordering by the
// CreateTime field.
func WithOrderByCreateTime(ascending bool) Option {
	return func(o *options) {
		o.withOrderByCreateTime = true
		o.ascending = ascending
	}
}
