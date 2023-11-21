// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-rate"
)

// NewLimiter creates a rate.Limiter.
func NewLimiter(limits []*rate.Limit, maxEntries int) (*rate.Limiter, error) {
	return rate.NewLimiter(
		limits,
		maxEntries,
		rate.WithQuotaStorageUsageMetric(rateLimitQuotaUsage),
		rate.WithQuotaStorageCapacityMetric(rateLimitQuotaStorageCapacity),
	)
}

// limit is a representation of a rate.Limit that is used when emitting a sys
// event to report the rate limit configuration.
type limit struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Per       string `json:"per"`
	Unlimited bool   `json:"unlimited"`
	Limit     uint64 `json:"limit"`
	Period    string `json:"period"`
}

type (
	actionLimits    []limit
	resourceActions map[string]actionLimits
	resources       map[string]resourceActions
)

// WriteLimitsSysEvent writes a sys event that contains all of the provided
// rate limits.
func WriteLimitsSysEvent(ctx context.Context, limits []*rate.Limit, maxEntries int) error {
	const op = "ratelimit.WritePoliciesSysEvent"

	e := make(resources)

	for _, l := range limits {
		var r resourceActions
		var a actionLimits
		var ok bool
		r, ok = e[l.Resource]
		if !ok {
			r = make(resourceActions)
			e[l.Resource] = r
		}

		a, ok = r[l.Action]
		if !ok {
			a = make(actionLimits, 0, 3)
		}
		a = append(a, limit{
			Resource:  l.Resource,
			Action:    l.Action,
			Per:       l.Per.String(),
			Unlimited: l.Unlimited,
			Limit:     l.MaxRequests,
			Period:    l.Period.String(),
		})
		r[l.Action] = a
	}
	event.WriteSysEvent(
		ctx,
		op,
		"controller api rate limits",
		"limits",
		e,
		"max_entries",
		maxEntries,
	)
	return nil
}
