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
		optionWithFieldMaskPaths: []string{},
		optionWithAggregateNames: false,
	}
}

const optionWithFieldMaskPaths = "optionWithFieldMaskPaths"

// WithFieldMaskPaths optional WithFieldMaskPaths, which are Paths from field_mask.proto
func WithFieldMaskPaths(fieldMaskPaths []string) Option {
	return func(o Options) {
		o[optionWithFieldMaskPaths] = fieldMaskPaths
	}
}

const optionWithAggregateNames = "optionWithAggregateNames"

// WithAggregateNames enables/disables the use of multiple aggregate names for Ticketers
func WithAggregateNames(enabled bool) Option {
	return func(o Options) {
		o[optionWithAggregateNames] = enabled
	}
}
