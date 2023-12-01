// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import "github.com/hashicorp/go-rate"

// NewLimiter creates a rate.Limiter.
func NewLimiter(limits []rate.Limit, maxEntries int) (*rate.Limiter, error) {
	return rate.NewLimiter(
		limits,
		maxEntries,
		rate.WithQuotaStorageUsageMetric(rateLimitQuotaUsage),
		rate.WithQuotaStorageCapacityMetric(rateLimitQuotaStorageCapacity),
	)
}
