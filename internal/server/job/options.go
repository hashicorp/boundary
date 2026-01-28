// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package servers

import (
	"time"
)

const defaultRotationFrequency = time.Hour

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
	withRotationFrequency   time.Duration
	withCertificateLifetime time.Duration
}

func getDefaultOptions() options {
	return options{
		withRotationFrequency: defaultRotationFrequency,
	}
}

// WithRotationFrequency provides an frequency for running a job. If the passed-in
// frequency is zero, it will not update the value, so that the default is used
// instead.
func WithRotationFrequency(with time.Duration) Option {
	return func(o *options) {
		o.withRotationFrequency = with
	}
}

// WithCertificateLifetime provides a way to specify the lifetime of generated
// roots
func WithCertificateLifetime(with time.Duration) Option {
	return func(o *options) {
		o.withCertificateLifetime = with
	}
}
