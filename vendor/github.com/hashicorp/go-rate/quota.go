// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rate

import (
	"sync"
	"time"
)

// Quota tracks the remaining number of requests that can be made within a time
// period.
type Quota struct {
	limit     *Limited
	used      uint64
	expiresAt time.Time

	mu sync.RWMutex
}

func (q *Quota) reset(l *Limited) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.used = 0
	q.expiresAt = time.Now().Add(l.Period)
	q.limit = l
}

// Expired checks if the quota has expired.
func (q *Quota) Expired() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return time.Now().After(q.expiresAt)
}

// Remaining is the number of requests that can be made prior to the quota
// expiring. If this returns zero, the request should not be allowed.
func (q *Quota) Remaining() uint64 {
	q.mu.RLock()
	defer q.mu.RUnlock()

	used := q.used
	if used > q.limit.MaxRequests {
		return 0
	}
	return q.limit.MaxRequests - used
}

// MaxRequests returns the maximum number of requests that can be made for
// this Quota.
func (q *Quota) MaxRequests() uint64 {
	q.mu.RLock()
	defer q.mu.RUnlock()

	return q.limit.MaxRequests
}

// ResetsIn returns the amount of time before the quota will expire.
func (q *Quota) ResetsIn() time.Duration {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.expiresAt.Sub(time.Now())
}

// Expiration returns the time that the quota will expire.
func (q *Quota) Expiration() time.Time {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.expiresAt
}

// Consume reduces the quota's remaining requests by one.
func (q *Quota) Consume() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.used++
}
