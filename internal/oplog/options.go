// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

import "github.com/hashicorp/go-dbw"

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(Options)

// Options = how options are represented
type Options map[string]any

func getDefaultOptions() Options {
	return Options{
		optionWithFieldMaskPaths:   []string{},
		optionWithSetToNullPaths:   []string{},
		optionWithAggregateNames:   false,
		optionWithOperationOptions: []dbw.Option{},
	}
}

const optionWithOperationOptions = "optionWithOptions"

// WithOperationOptions represents an optional set dbw.Options.  (see the dbw
// package for more info on the options)
func WithOperationOptions(opt ...dbw.Option) Option {
	return func(o Options) {
		o[optionWithOperationOptions] = opt
	}
}

const optionWithFieldMaskPaths = "optionWithFieldMaskPaths"

// WithFieldMaskPaths represents an optional set of symbolic field paths (for example: "f.a", "f.b.d") used
// to specify a subset of fields that should be updated. (see google.golang.org/genproto/protobuf/field_mask)
func WithFieldMaskPaths(fieldMaskPaths []string) Option {
	return func(o Options) {
		o[optionWithFieldMaskPaths] = fieldMaskPaths
	}
}

const optionWithSetToNullPaths = "optionWithSetToNullPaths"

// WithSetToNullPaths represents an optional set of symbolic field paths (for example: "f.a", "f.b.d") used
// to specify a subset of fields that should be set to null. (see google.golang.org/genproto/protobuf/field_mask)
func WithSetToNullPaths(setToNullPaths []string) Option {
	return func(o Options) {
		o[optionWithSetToNullPaths] = setToNullPaths
	}
}

const optionWithAggregateNames = "optionWithAggregateNames"

// WithAggregateNames enables/disables the use of multiple aggregate names for Ticketers
func WithAggregateNames(enabled bool) Option {
	return func(o Options) {
		o[optionWithAggregateNames] = enabled
	}
}
