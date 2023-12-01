// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"net/http"

	"github.com/hashicorp/go-rate"
)

// Limiter is used to provide rate limiting. This is the interface implemented
// by both rate.Limiter and rate.NopLimiter.
type Limiter interface {
	SetPolicyHeader(string, string, http.Header) error
	SetUsageHeader(*rate.Quota, http.Header)
	Allow(string, string, string, string) (bool, *rate.Quota, error)
	Shutdown() error
}

// NewLimiter creates a rate.Limiter.
func NewLimiter(limits []rate.Limit, maxEntries int) (*rate.Limiter, error) {
	return rate.NewLimiter(
		limits,
		maxEntries,
		rate.WithQuotaStorageUsageMetric(rateLimitQuotaUsage),
		rate.WithQuotaStorageCapacityMetric(rateLimitQuotaStorageCapacity),
	)
}
