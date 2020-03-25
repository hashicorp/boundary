package oplog

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(Options)

// Options = how options are represented
type Options map[string]interface{}

func getDefaultOptions() Options {
	return Options{
		optionWithFieldMask:      "",
		optionWithAggregateNames: false,
	}
}

const optionWithFieldMask = "optionWithFieldMask"

// WithFieldMask optional fieldMask
func WithFieldMask(fieldMask string) Option {
	return func(o Options) {
		o[optionWithFieldMask] = fieldMask
	}
}

const optionWithAggregateNames = "optionWithAggregateNames"

// WithAggregateNames enables/disables the use of multiple aggregate names for Ticketers
func WithAggregateNames(enabled bool) Option {
	return func(o Options) {
		o[optionWithAggregateNames] = enabled
	}
}
