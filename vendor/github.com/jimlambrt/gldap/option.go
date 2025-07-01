// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"io"
	"reflect"
)

// Option defines a common functional options type which can be used in a
// variadic parameter pattern.
type Option func(interface{})

// applyOpts takes a pointer to the options struct as a set of default options
// and applies the slice of opts as overrides.
func applyOpts(opts interface{}, opt ...Option) {
	for _, o := range opt {
		if o == nil { // ignore any nil Options
			continue
		}
		o(opts)
	}
}

type generalOptions struct {
	withWriter io.Writer
}

func generalDefaults() generalOptions {
	return generalOptions{}
}

func getGeneralOpts(opt ...Option) generalOptions {
	opts := generalDefaults()
	applyOpts(&opts, opt...)
	return opts
}

// WithWriter allows you to specify an optional writer.
func WithWriter(w io.Writer) Option {
	return func(o interface{}) {
		if o, ok := o.(*generalOptions); ok {
			if !isNil(w) {
				o.withWriter = w
			}
		}
	}
}

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
