package api

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
	withScopeId string
}

func getDefaultOptions() options {
	return options{
		withScopeId: "",
	}
}

func WithScopeId(id string) Option {
	return func(o *options) {
		o.withScopeId = id
	}
}
