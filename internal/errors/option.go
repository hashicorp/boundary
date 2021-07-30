package errors

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*Options)

// Options - how Options are represented.
type Options struct {
	withCode       Code
	withErrWrapped error
	withErrMsg     string
	withOp         Op
	withoutEvent   bool
}

func getDefaultOptions() Options {
	return Options{}
}

// WithErrCode provides an option to provide an error to wrap when creating a
// new error.
func WithWrap(e error) Option {
	return func(o *Options) {
		o.withErrWrapped = e
	}
}

// WithMsg provides an option to provide a message when creating a new
// error.
func WithMsg(msg string) Option {
	return func(o *Options) {
		o.withErrMsg = msg
	}
}

// WithOp provides an option to provide the operation that's raising/propagating
// the error.
func WithOp(op Op) Option {
	return func(o *Options) {
		o.withOp = op
	}
}

// WithCode provides an option to provide a code when creating a new
// error.
func WithCode(code Code) Option {
	return func(o *Options) {
		o.withCode = code
	}
}

func WithoutEvent() Option {
	return func(o *Options) {
		o.withoutEvent = true
	}
}
