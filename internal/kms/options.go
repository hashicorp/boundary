package kms

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*Options)

// Options = how Options are represented
type Options struct {
	withParentKeyId string
}

func getDefaultOptions() Options {
	return Options{
		withParentKeyId: "",
	}
}

// WithParentKeyId provides an optional parent key id
func WithParentKeyId(id string) Option {
	return func(o *Options) {
		o.withParentKeyId = id
	}
}
