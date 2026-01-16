// Copyright IBM Corp. 2020, 2025

package config

import (
	"crypto/rand"
	"io"
	"os"
	"testing"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) (options, error) {
	opts, err := getDefaultOptions()
	if err != nil {
		return opts, err
	}
	for _, o := range opt {
		if o == nil {
			continue
		}
		err = o(&opts)
		if err != nil {
			return opts, err
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments
type Option func(*options) error

// options = how options are represented
type options struct {
	withSysEventsEnabled       bool
	withAuditEventsEnabled     bool
	withObservationsEnabled    bool
	withIPv6Enabled            bool
	testWithErrorEventsEnabled bool
	withRandomReader           io.Reader
}

func getDefaultOptions() (options, error) {
	opts := options{}

	sysEvents, err := parseutil.ParseBool(os.Getenv("BOUNDARY_ENABLE_TEST_SYS_EVENTS"))
	if err != nil {
		return opts, err
	}
	opts.withSysEventsEnabled = sysEvents

	auditEvents, err := parseutil.ParseBool(os.Getenv("BOUNDARY_ENABLE_TEST_AUDIT_EVENTS"))
	if err != nil {
		return opts, err
	}
	opts.withAuditEventsEnabled = auditEvents

	obs, err := parseutil.ParseBool(os.Getenv("BOUNDARY_ENABLE_TEST_OBSERVATIONS"))
	if err != nil {
		return opts, err
	}
	opts.withObservationsEnabled = obs

	ipv6, err := parseutil.ParseBool(os.Getenv("BOUNDARY_ENABLE_TEST_IPV6"))
	if err != nil {
		return opts, err
	}
	opts.withIPv6Enabled = ipv6

	errEvents, err := parseutil.ParseBool(os.Getenv("BOUNDARY_ENABLE_TEST_ERROR_EVENTS"))
	if err != nil {
		return opts, err
	}
	opts.testWithErrorEventsEnabled = errEvents

	opts.withRandomReader = rand.Reader

	return opts, nil
}

// WithSysEventsEnabled provides an option for enabling system events
func WithSysEventsEnabled(enable bool) Option {
	return func(o *options) error {
		o.withSysEventsEnabled = enable
		return nil
	}
}

// WithAuditEventsEnabled provides an option for enabling audit events
func WithAuditEventsEnabled(enable bool) Option {
	return func(o *options) error {
		o.withAuditEventsEnabled = enable
		return nil
	}
}

// WithObservationsEnabled provides an option for enabling observation events
func WithObservationsEnabled(enable bool) Option {
	return func(o *options) error {
		o.withObservationsEnabled = enable
		return nil
	}
}

// WithIPv6Enabled provides an option for enabling network ipv6 addresses
func WithIPv6Enabled(enable bool) Option {
	return func(o *options) error {
		o.withIPv6Enabled = enable
		return nil
	}
}

// WithRandomReader provides an option to specify a random reader.
func WithRandomReader(reader io.Reader) Option {
	return func(o *options) error {
		o.withRandomReader = reader
		return nil
	}
}

// TestWithErrorEventsEnabled provides an option for enabling error events
// during tests.
func TestWithErrorEventsEnabled(_ testing.TB, enable bool) Option {
	return func(o *options) error {
		o.testWithErrorEventsEnabled = enable
		return nil
	}
}
