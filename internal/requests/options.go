package requests

func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments. Some of these are used for
// types within the handlers package, and some are for handlers to re-use across
// the various handler types.
type Option func(*options)

// options = how options are represented
type options struct {
	withUserId string
}

func getDefaultOptions() options {
	return options{}
}

// WithUserId specifies a user ID with which to populate the returned
// RequestContext
func WithUserId(userId string) Option {
	return func(o *options) {
		o.withUserId = userId
	}
}
