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
	withPublicId    string
	withName        string
	withScope       *Scope
	withDescription string
}

func getDefaultOptions() options {
	return options{
		withPublicId:    "",
		withScope:       nil,
		withDescription: "",
		withName:        "",
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
