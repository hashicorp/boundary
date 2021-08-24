package schema

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
	withMigrationStates map[string]migrationState
	withDeleteLog       bool
}

func getDefaultOptions() options {
	return options{}
}

// WithMigrationStates provides an optional migration states.
func WithMigrationStates(states map[string]migrationState) Option {
	return func(o *options) {
		o.withMigrationStates = states
	}
}

// WithDeleteLog provides an option to specify the deletion of log entries.
func WithDeleteLog(del bool) Option {
	return func(o *options) {
		o.withDeleteLog = del
	}
}
