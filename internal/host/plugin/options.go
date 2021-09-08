package plugin

// getOpts - iterate the inbound Options and return a struct
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
	withLimit       int
	withAttributes map[string]interface{}
	withSecrets    map[string]interface{}
}

func getDefaultOptions() options {
	return options{
		withDescription: "",
		withName:        "",
		withAttributes:  make(map[string]interface{}),
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

// WithAttributes provides an optional attributes field.
func WithAttributes(attrs map[string]interface{}) Option {
	return func(o *options) {
		o.withAttributes = attrs
	}
}

// WithSecrets provides an optional secrets field.
func WithSecrets(secrets map[string]interface{}) Option {
	return func(o *options) {
		o.withSecrets = secrets
	}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are
// returned. If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}
