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
	withErrWrapped error
	withErrMsg     string
	withErrCode    *ErrCode
}

func getDefaultOptions() Options {
	return Options{}
}

// WithErrCode provides an option to provide an ErrCode when creating a new
// error.
func WithErrCode(c ErrCode) Option {
	return func(o *Options) {
		o.withErrCode = &c
	}
}

// WithErrCode provides an option to provide an error to wrap when creating a
// new error.
func WithWrap(e error) Option {
	return func(o *Options) {
		o.withErrWrapped = e
	}
}

// WithErrorMsg provides an option to provide a message when creating a new
// error.
func WithErrorMsg(msg string) Option {
	return func(o *Options) {
		o.withErrMsg = msg
	}
}
