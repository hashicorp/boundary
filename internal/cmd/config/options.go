// Copyright (c) HashiCorp, Inc.

package config

import "testing"

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withSysEventsEnabled       bool
	withAuditEventsEnabled     bool
	withObservationsEnabled    bool
	testWithErrorEventsEnabled bool
}

func getDefaultOptions() options {
	return options{}
}

// WithSysEventsEnabled provides an option for enabling system events
func WithSysEventsEnabled(enable bool) Option {
	return func(o *options) {
		o.withSysEventsEnabled = enable
	}
}

// WithAuditEventsEnabled provides an option for enabling audit events
func WithAuditEventsEnabled(enable bool) Option {
	return func(o *options) {
		o.withAuditEventsEnabled = enable
	}
}

// WithObservationsEnabled provides an option for enabling observation events
func WithObservationsEnabled(enable bool) Option {
	return func(o *options) {
		o.withObservationsEnabled = enable
	}
}

// TestWithErrorEventsEnabled provides an option for enabling error events
// during tests.
func TestWithErrorEventsEnabled(_ testing.TB, enable bool) Option {
	return func(o *options) {
		o.testWithErrorEventsEnabled = enable
	}
}
