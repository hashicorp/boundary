package password

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
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
	withName        string
	withDescription string
	password        string
	withPassword    bool
}

func getDefaultOptions() options {
	return options{}
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

// WithPassword provides an optional password.
func WithPassword(password string) Option {
	return func(o *options) {
		o.password = password
		o.withPassword = true
	}
}
