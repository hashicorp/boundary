// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rate

import (
	"fmt"
	"math"
	"net/http"
	"sync"
)

type quotaFetcher interface {
	// fetch will get a Quota for the provided key.
	// If no quota is found, a new one will be created using the provided Limit.
	fetch(key string, limit *Limited) (*Quota, error)
	// shutdown stops a quotaFetcher.
	shutdown() error
}

// Limiter is used to determine if a request for a given resource and action
// should be allowed.
// TODO: expand this doc
type Limiter struct {
	policies     *limitPolicies
	policyHeader string
	usageHeader  string

	mu sync.RWMutex

	quotaFetcher quotaFetcher
}

// NewLimiter will create a Limiter with the provided limits and max size. The
// limits must each be unique, where uniqueness is determined by the
// combination of "resource", "action", and "per". The maxSize must be greater
// than zero. This size is the number of individual quotas that can be stored
// in memory at any given time. Once this size is reached, requests that would
// result in a new quota being inserted will not be allowed. Requests that
// correspond to existing quotas will still be processed as normal. Space will
// become available once quotas expire and are removed.
//
// Supported options are:
//   - WithNumberBuckets: Sets the number of buckets used for expiring quotas.
//     This must be greater than zero, and defaults to DefaultNumberBuckets. A
//     larger number of buckets can increase the efficiency at which expired
//     quotas are deleted to free up space. However, it does also marginally
//     increase the amount of memory needed, and can increase the frequency
//     in which the delete routine runs and must acquire a lock.
//   - WithPolicyHeader: Sets the HTTP Header key to use when setting the policy
//     header via SetPolicyHeader. This defaults to "RateLimit-Policy".
//   - WithUsageHeader: Sets the HTTP Header key to use when setting the usage
//     header via SetUsageHeader. This defaults to "RateLimit".
//   - WithQuotaStorageCapacityMetric: Provides a gauge metric to report the
//     total number of Quotas that can be stored by the Limiter. The default is
//     to not report this metric.
//   - WithQuotaStorageUsageMetric: Provides a gauge metric to report the
//     current number of Quotas that are being stored by the Limiter. The
//     default is to not report this metric.
func NewLimiter(limits []Limit, maxSize int, o ...Option) (*Limiter, error) {
	const op = "rate.NewLimiter"

	switch {
	case len(limits) <= 0:
		return nil, fmt.Errorf("%s: %w", op, ErrEmptyLimits)
	case allUnlimited(limits):
		return nil, fmt.Errorf("%s: %w", op, ErrAllUnlimited)
	}

	opts := getOpts(o...)

	policies, err := newLimitPolicies(limits)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	s, err := newExpirableStore(maxSize, policies.maxPeriod, o...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	l := &Limiter{
		policies:     policies,
		quotaFetcher: s,
		policyHeader: opts.withPolicyHeader,
		usageHeader:  opts.withUsageHeader,
	}

	return l, nil
}

// SetPolicyHeader sets the rate limit policy HTTP header for the provided
// resource and action.
func (l *Limiter) SetPolicyHeader(resource, action string, header http.Header) error {
	pol, err := l.policies.get(resource, action)
	if err != nil {
		return err
	}
	p := pol.httpHeaderValue()
	if p == "" {
		return nil
	}

	header.Set(l.policyHeader, pol.httpHeaderValue())
	return nil
}

// SetUsageHeader sets the rate limit usage HTTP header using the provided
// Quota.
func (l *Limiter) SetUsageHeader(quota *Quota, header http.Header) {
	if quota == nil {
		return
	}

	header.Set(
		l.usageHeader,
		fmt.Sprintf("limit=%d, remaining=%d, reset=%.0f", quota.MaxRequests(), quota.Remaining(), math.Ceil(quota.ResetsIn().Seconds())),
	)
}

// Allow checks if a request for the given resource and action should be allowed.
// A request is not allowed if:
//   - Any of the associated quotas have been exhausted.
//   - A new quota needs to be stored but there is no available space to store it.
//     The error returned in this case will be a ErrLimiterFull with a provided
//     RetryIn duration. Callers should use this time as an estimation of when
//     the limiter should no longer be full.
//   - There is no corresponding limit for the resource and action.
//
// If all of the limits for the given resource and action are Unlimited, the
// action will be allowed, but the quota returned will be nil.
func (l *Limiter) Allow(resource, action, ip, authToken string) (allowed bool, quota *Quota, err error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	allowOrder := []LimitPer{
		LimitPerTotal,
		LimitPerIPAddress,
		LimitPerAuthToken,
	}

	quotas := make(map[LimitPer]*Quota, len(allowOrder))
	keys := map[LimitPer]string{
		LimitPerTotal:     string(LimitPerTotal),
		LimitPerIPAddress: ip,
		LimitPerAuthToken: authToken,
	}

	allowed = true
	for per, id := range keys {
		var limit Limit
		var policy *limitPolicy
		policy, err = l.policies.get(resource, action)
		if err != nil {
			allowed = false
			return
		}

		limit, err = policy.limit(per)
		if err != nil {
			allowed = false
			return
		}

		switch ll := limit.(type) {
		case *Unlimited:
			continue
		case *Limited:
			var q *Quota
			q, err = l.quotaFetcher.fetch(id, ll)
			if err != nil {
				allowed = false
				return
			}

			if q.Remaining() <= 0 {
				allowed = false
				quota = q
				return
			}

			quotas[per] = q
		}
	}

	for _, per := range allowOrder {
		q, ok := quotas[per]
		if !ok {
			// we may not have a quota if the corresponding limit is Unlimited.
			continue
		}
		q.Consume()
		if quota == nil || q.Remaining() < quota.Remaining() {
			quota = q
		}
	}

	return
}

// Shutdown stops a Limiter. After calling this, any future calls to Allow
// will result in ErrStopped being returned.
func (l *Limiter) Shutdown() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.quotaFetcher.shutdown()
}

func allUnlimited(limits []Limit) bool {
	for _, l := range limits {
		switch l.(type) {
		case *Limited:
			return false
		}
	}
	return true
}
