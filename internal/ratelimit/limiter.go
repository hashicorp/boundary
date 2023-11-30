// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"net/http"

	"github.com/hashicorp/boundary/internal/event"
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
func WriteLimitsSysEvent(ctx context.Context, limits []rate.Limit, maxEntries int) error {
	const op = "ratelimit.WritePoliciesSysEvent"

	e := make(resources)

	for _, l := range limits {
		var r resourceActions
		var a actionLimits
		var ok bool
		r, ok = e[l.GetResource()]
		if !ok {
			r = make(resourceActions)
			e[l.GetResource()] = r
		}

		a, ok = r[l.GetAction()]
		if !ok {
			a = make(actionLimits, 0, 3)
		}

		switch ll := l.(type) {
		case *rate.Limited:
			a = append(a, limit{
				Resource:  ll.Resource,
				Action:    ll.Action,
				Per:       ll.Per.String(),
				Unlimited: false,
				Limit:     ll.MaxRequests,
				Period:    ll.Period.String(),
			})
		case *rate.Unlimited:
			a = append(a, limit{
				Resource:  ll.Resource,
				Action:    ll.Action,
				Per:       ll.Per.String(),
				Unlimited: true,
			})
		}
		r[l.GetAction()] = a
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
