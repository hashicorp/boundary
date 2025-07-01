// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

type controlOptions struct {
	withGrace        int
	withExpire       int
	withErrorCode    int
	withCriticality  bool
	withControlValue string

	// test options
	withTestType     string
	withTestToString string
}

func controlDefaults() controlOptions {
	return controlOptions{
		withGrace:     -1,
		withExpire:    -1,
		withErrorCode: -1,
	}
}

func getControlOpts(opt ...Option) controlOptions {
	opts := controlDefaults()
	applyOpts(&opts, opt...)
	return opts
}

// WithGraceAuthNsRemaining specifies the number of grace authentication
// remaining.
func WithGraceAuthNsRemaining(remaining uint) Option {
	return func(o interface{}) {
		if o, ok := o.(*controlOptions); ok {
			o.withGrace = int(remaining)
		}
	}
}

// WithSecondsBeforeExpiration specifies the number of seconds before a password
// will expire
func WithSecondsBeforeExpiration(seconds uint) Option {
	return func(o interface{}) {
		if o, ok := o.(*controlOptions); ok {
			o.withExpire = int(seconds)
		}
	}
}

// WithErrorCode specifies the error code
func WithErrorCode(code uint) Option {
	return func(o interface{}) {
		if o, ok := o.(*controlOptions); ok {
			o.withErrorCode = int(code)
		}
	}
}

// WithCriticality specifies the criticality
func WithCriticality(criticality bool) Option {
	return func(o interface{}) {
		if o, ok := o.(*controlOptions); ok {
			o.withCriticality = criticality
		}
	}
}

// WithControlValue specifies the control value
func WithControlValue(value string) Option {
	return func(o interface{}) {
		if o, ok := o.(*controlOptions); ok {
			o.withControlValue = value
		}
	}
}

func withTestType(s string) Option {
	return func(o interface{}) {
		if o, ok := o.(*controlOptions); ok {
			o.withTestType = s
		}
	}
}

func withTestToString(s string) Option {
	return func(o interface{}) {
		if o, ok := o.(*controlOptions); ok {
			o.withTestToString = s
		}
	}
}
