package servers

import "time"

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
	withLimit      int
	withLiveness   time.Duration
	withUpdateTags bool
}

func getDefaultOptions() options {
	return options{
		withLimit:    0,
		withLiveness: 0,
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

// WithLiveness indicates how far back we want to search for server entries.
// Use 0 for the default liveness (15 seconds). A liveness value of -1 removes
// the liveliness condition.
func WithLiveness(liveness time.Duration) Option {
	return func(o *options) {
		o.withLiveness = liveness
	}
}

// WithUpdateTags indicates that we should perform tag updates in the DB.
// This would happen on first sync from a worker after startup or (eventually,
// perhaps), after a SIGHUP.
func WithUpdateTags(updateTags bool) Option {
	return func(o *options) {
		o.withUpdateTags = updateTags
	}
}
