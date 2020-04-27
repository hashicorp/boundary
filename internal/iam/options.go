package iam

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(Options)

// Options = how options are represented
type Options map[string]interface{}

func getDefaultOptions() Options {
	return Options{
		optionWithPublicId:     "",
		optionWithFriendlyName: "",
		optionWithScope:        nil,
		optionWithDescription:  "",
	}
}

const optionWithPublicId = "optionWithPublicId"

// WitPublicId provides an optional public id
func WitPublicId(id string) Option {
	return func(o Options) {
		o[optionWithPublicId] = id
	}
}

const optionWithDescription = "optionWithDescription"

// WithDescription provides an optional description
func WithDescription(desc string) Option {
	return func(o Options) {
		o[optionWithDescription] = desc
	}
}

const optionWithScope = "optionWithScope"

// WithScope provides an optional scope
func WithScope(s *Scope) Option {
	return func(o Options) {
		o[optionWithScope] = s
	}
}

const optionWithFriendlyName = "optionWithFriendlyName"

// WithFriendlyName provides an option to search by a friendly name
func WithFriendlyName(name string) Option {
	return func(o Options) {
		o[optionWithFriendlyName] = name
	}
}
