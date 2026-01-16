// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"github.com/hashicorp/boundary/globals"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	subsystem = "controller_api_ratelimiter"
)

var (
	rateLimitQuotaStorageCapacity prometheus.Gauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: subsystem,
			Name:      "quota_storage_capacity",
			Help:      "Guague of the number if quotas that can be stored by the rate limiter",
		},
	)
	rateLimitQuotaUsage prometheus.Gauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: subsystem,
			Name:      "quota_storage_usage",
			Help:      "Guague of the number if quotas that are currently being stored by the rate limiter",
		},
	)
)

// InitializeMetrics initializes the metrics for visibility into the rate limiter.
func InitializeMetrics(r prometheus.Registerer) {
	if r == nil {
		return
	}
	r.MustRegister(
		rateLimitQuotaStorageCapacity,
		rateLimitQuotaUsage,
	)
}
