package schema

import "github.com/hashicorp/boundary/internal/db/schema/internal/edition"

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
	withEditions  edition.Editions
	withDeleteLog bool
}

func getDefaultOptions() options {
	return options{}
}

// WithEditions provides an optional migration states.
func WithEditions(editions edition.Editions) Option {
	return func(o *options) {
		o.withEditions = editions
	}
}

// WithDeleteLog provides an option to specify the deletion of log entries.
func WithDeleteLog(del bool) Option {
	return func(o *options) {
		o.withDeleteLog = del
	}
}
