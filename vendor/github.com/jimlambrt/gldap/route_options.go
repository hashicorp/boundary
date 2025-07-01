// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

type routeOptions struct {
	withLabel  string
	withBaseDN string
	withFilter string
	withScope  Scope
}

func routeDefaults() routeOptions {
	return routeOptions{}
}

func getRouteOpts(opt ...Option) routeOptions {
	opts := routeDefaults()
	applyOpts(&opts, opt...)
	return opts
}

// WithLabel specifies an optional label for the route
func WithLabel(l string) Option {
	return func(o interface{}) {
		if o, ok := o.(*routeOptions); ok {
			o.withLabel = l
		}
	}
}

// WithBaseDN specifies an optional base DN to associate with a Search route
func WithBaseDN(dn string) Option {
	return func(o interface{}) {
		if o, ok := o.(*routeOptions); ok {
			o.withBaseDN = dn
		}
	}
}

// WithFilter specifies an optional filter to associate with a Search route
func WithFilter(filter string) Option {
	return func(o interface{}) {
		if o, ok := o.(*routeOptions); ok {
			o.withFilter = filter
		}
	}
}

// WithScope specifies and optional scope to associate with a Search route
func WithScope(s Scope) Option {
	return func(o interface{}) {
		if o, ok := o.(*routeOptions); ok {
			o.withScope = s
		}
	}
}
