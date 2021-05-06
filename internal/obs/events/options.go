package event

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
	withDetails map[string]interface{}
	withHeader  map[string]interface{}
}

func getDefaultOptions() options {
	return options{}
}

func WithDetails(d map[string]interface{}) Option {
	return func(o *options) {
		o.withDetails = d
	}
}

func WithHeader(d map[string]interface{}) Option {
	return func(o *options) {
		o.withHeader = d
	}
}
