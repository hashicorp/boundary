// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package metric provides interfaces for the types of metrics that the
// rate.Limiter can use to aid in monitoring the limiter.
package metric

// Gauge is a metric that can increase and decrease over time.
type Gauge interface {
	Set(float64)
}
