package iam

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
		optionWithFriendlyName: "",
		optionAsRootUser:       false,
		optionWithOwnerId:      uint32(0),
		optionWithScope:        nil,
	}
}

const optionWithScope = "optionWithScope"

// WithScope provides an optional scope
func WithScope(s *Scope) Option {
	return func(o Options) {
		o[optionWithScope] = s
	}
}

const optionWithOplog = "optionWithOplog"

// WithCommit provides an option to commit the transaction
func WithOplog(commitTx bool) Option {
	return func(o Options) {
		o[optionWithCommit] = commitTx
	}
}

const optionWithCommit = "optionWithCommit"

// WithCommit provides an option to commit the transaction
func WithCommit(commitTx bool) Option {
	return func(o Options) {
		o[optionWithCommit] = commitTx
	}
}

const optionWithOwnerId = "optionWithOwnerId"

// WithOwnerId provides an optional owner id
func WithOwnerId(id uint32) Option {
	return func(o Options) {
		o[optionWithOwnerId] = id
	}
}

const optionWithFriendlyName = "optionWithFriendlyName"

// WithFriendlyName provides an option to search by a friendly name
func WithFriendlyName(name string) Option {
	return func(o Options) {
		o[optionWithFriendlyName] = name
	}
}

const optionAsRootUser = "optionAsRootUser"

// AsRootUser provides an option to specify this is a root user
func AsRootUser(b bool) Option {
	return func(o Options) {
		o[optionAsRootUser] = b
	}
}
