package authtoken

import "time"

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
	withTokenValue               bool
	withTokenTimeToLiveDuration  time.Duration
	withTokenTimeToStaleDuration time.Duration
	withLimit                    int
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

// WithTokenTimeToLiveDuration allows setting the auth token time-to-live.
func WithTokenTimeToLiveDuration(ttl time.Duration) Option {
	return func(o *options) {
		o.withTokenTimeToLiveDuration = ttl
	}
}

// WithTokenTimeToStaleDuration allows setting the auth token staleness duration.
func WithTokenTimeToStaleDuration(dur time.Duration) Option {
	return func(o *options) {
		o.withTokenTimeToStaleDuration = dur
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}
