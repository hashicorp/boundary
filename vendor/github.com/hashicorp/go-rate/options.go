// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rate

import "github.com/hashicorp/go-rate/metric"

const (
	// DefaultNumberBuckets is the default number of buckets created for the quota store.
	DefaultNumberBuckets = 61

	// DefaultPolicyHeader is the default HTTP header for reporting the rate limit policy.
	DefaultPolicyHeader = "RateLimit-Policy"

	// DefaultUsageHeader is the default HTTP header for reporting quota usage.
	DefaultUsageHeader = "RateLimit"
)

// nilGauge is a gauge that does nothing.
type nilGauge struct{}

func (n *nilGauge) Set(_ float64) {}

// Option provides a way to pass optional arguments.
type Option func(*options)

func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

type options struct {
	withNumberBuckets              int
	withPolicyHeader               string
	withUsageHeader                string
	withQuotaStorageCapacityMetric metric.Gauge
	withQuotaStorageUsageMetric    metric.Gauge
}

func getDefaultOptions() options {
	return options{
		withNumberBuckets:              DefaultNumberBuckets,
		withPolicyHeader:               DefaultPolicyHeader,
		withUsageHeader:                DefaultUsageHeader,
		withQuotaStorageCapacityMetric: &nilGauge{},
		withQuotaStorageUsageMetric:    &nilGauge{},
	}
}

// WithNumberBuckets is used to set the number of buckets created for the quota store.
func WithNumberBuckets(n int) Option {
	return func(o *options) {
		o.withNumberBuckets = n
	}
}

// WithPolicyHeader is used to set the header key used by the Limiter for
// reporting the limit policy.
func WithPolicyHeader(h string) Option {
	return func(o *options) {
		o.withPolicyHeader = h
	}
}

// WithUsageHeader is used to set the header key used by the Limiter for
// reporting quota usage.
func WithUsageHeader(h string) Option {
	return func(o *options) {
		o.withUsageHeader = h
	}
}

// WithQuotaStorageCapacityMetric is used to provide a metric that will record
// the total capacity available to the Limiter for storing Quotas.
func WithQuotaStorageCapacityMetric(g metric.Gauge) Option {
	return func(o *options) {
		switch {
		case g == nil:
			o.withQuotaStorageUsageMetric = &nilGauge{}
		default:
			o.withQuotaStorageCapacityMetric = g
		}
	}
}

// WithQuotaStorageUsageMetric is used to provide a metric that will record the
// current number of Quotas that are being stored by the Limiter.
func WithQuotaStorageUsageMetric(g metric.Gauge) Option {
	return func(o *options) {
		switch {
		case g == nil:
			o.withQuotaStorageUsageMetric = &nilGauge{}
		default:
			o.withQuotaStorageUsageMetric = g
		}
	}
}
