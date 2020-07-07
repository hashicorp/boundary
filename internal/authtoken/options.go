package authtoken

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
	withTokenValue bool
}

func getDefaultOptions() options {
	return options{}
}

// withTokenValue allows the auth token value to be included in the lookup response.
// This is purposefully not exported as it should only be used internally by the auth token repository itself.
func withTokenValue() Option {
	return func(o *options) {
		o.withTokenValue = true
	}
}
