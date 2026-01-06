// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	withErrMsgArgs []any
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
// error.  If args are provided, the the msg string is used as a fmt specifier
// for the arguments and the resulting string is used as the msg.
func WithMsg(msg string, args ...any) Option {
	return func(o *Options) {
		o.withErrMsg = msg
		o.withErrMsgArgs = args
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

// WithoutEvent provides an option to suppress the event when wrapping or
// creating a new error.
func WithoutEvent() Option {
	return func(o *Options) {
		o.withoutEvent = true
	}
}
