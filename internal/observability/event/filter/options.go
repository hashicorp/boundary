package node

import "net/url"

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withAllow  []string
	withDeny   []string
	withSchema *url.URL
}

func getDefaultOptions() options {
	return options{}
}

// WithSchema is an optional schema for the cloudevents
func WithSchema(url *url.URL) Option {
	return func(o *options) {
		o.withSchema = url
	}
}

// WithAllow is an optional set of allow filters
func WithAllow(f ...string) Option {
	return func(o *options) {
		o.withAllow = f
	}
}

// WithDeny is an optional set of deny filters
func WithDeny(f ...string) Option {
	return func(o *options) {
		o.withDeny = f
	}
}
