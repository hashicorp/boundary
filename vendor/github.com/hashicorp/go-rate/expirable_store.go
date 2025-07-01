// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rate

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-rate/metric"
)

// bucketSizeThreshold is used to determine when a bucket should get
// reallocated to release some memory to get garbage collected. While not
// officially documented, and therefore subject to change, a map will grow once
// it requires more than 8 keys, so that is used as the threshold when deciding
// to re-allocate a bucket's entries map.
const bucketSizeThreshold = 8

type entry struct {
	key   string
	value *Quota

	bucket int
}

type bucket struct {
	entries map[string]*entry

	expiresAt time.Time
}

// TODO document this, in particular provide some details around:
// - the purpose and use of "buckets"
type expirableStore struct {
	maxSize int

	items map[string]*entry

	buckets            []bucket
	bucketTTL          time.Duration
	numberBuckets      int
	nextBucketToExpire int
	capacityMetric     metric.Gauge
	usageMetric        metric.Gauge

	mu sync.Mutex

	pool sync.Pool

	cancelFunc context.CancelFunc
	ctx        context.Context
}

func newExpirableStore(maxSize int, maxEntryTTL time.Duration, o ...Option) (*expirableStore, error) {
	const op = "rate.newExpirableStore"

	opts := getOpts(o...)

	switch {
	case maxSize <= 0:
		return nil, fmt.Errorf("%s: max size must be greater than zero: %w", op, ErrInvalidMaxSize)
	case maxEntryTTL <= 0:
		return nil, fmt.Errorf("%s: max entry ttl must be greater than zero: %w", op, ErrInvalidParameter)
	case opts.withNumberBuckets <= 0:
		return nil, fmt.Errorf("%s: number of buckets must be greater than zero: %w", op, ErrInvalidNumberBuckets)
	}

	var bucketTTL time.Duration
	switch opts.withNumberBuckets {
	case 1:
		bucketTTL = maxEntryTTL
	default:
		bucketTTL = maxEntryTTL / time.Duration(opts.withNumberBuckets-1)
	}

	buckets := make([]bucket, opts.withNumberBuckets)
	for i := 0; i < opts.withNumberBuckets; i++ {
		buckets[i] = bucket{
			entries: make(map[string]*entry),
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &expirableStore{
		maxSize:       maxSize,
		items:         make(map[string]*entry, maxSize),
		buckets:       buckets,
		bucketTTL:     bucketTTL,
		numberBuckets: opts.withNumberBuckets,
		pool: sync.Pool{
			New: func() any {
				return &entry{
					value: &Quota{},
				}
			},
		},
		cancelFunc:     cancel,
		ctx:            ctx,
		capacityMetric: opts.withQuotaStorageCapacityMetric,
		usageMetric:    opts.withQuotaStorageUsageMetric,
	}
	s.capacityMetric.Set(float64(maxSize))
	s.usageMetric.Set(float64(0))

	go s.deleteExpired()
	return s, nil
}

func (s *expirableStore) shutdown() error {
	s.cancelFunc()
	return nil
}

func (s *expirableStore) deleteExpired() {
	ticker := time.NewTicker(s.bucketTTL)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.emptyExpiredBucket()
		}
	}
}

// TODO: document this
func (s *expirableStore) fetch(id string, limit *Limited) (*Quota, error) {
	select {
	case <-s.ctx.Done():
		return nil, ErrStopped
	default:
		// continue
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := join(limit.Resource, limit.Action, string(limit.Per), id)

	e, ok := s.items[key]
	switch {
	case !ok:
		e = s.pool.Get().(*entry)
		e.key = key
		e.value.reset(limit)
		if err := s.add(e); err != nil {
			s.pool.Put(e)
			return nil, err
		}
	case e.value.Expired():
		s.removeFromBucket(e)
		e.value.reset(limit)
		s.addToBucket(e)
	}

	s.usageMetric.Set(float64(len(s.items)))

	return e.value, nil
}

// add attempts to add an entry to the store. If the store has reached its
// max capacity, ErrLimiterFull is returned.
//
// add should always be called by a function that first acquires a lock
func (s *expirableStore) add(e *entry) error {
	const op = "rate.(expirableStore).add"
	if s.mu.TryLock() {
		panic(fmt.Sprintf("%s: called without lock", op))
	}
	if _, ok := s.items[e.key]; !ok && len(s.items) >= s.maxSize {
		// This is hopefully a reasonable estimate of when space will free up.
		// However, it might not be accurate:
		// 1. This is really an upper-bound on when the delete go routine
		// should run again. So space may free up sooner if the routine runs at
		// an earlier time.
		// 2. When the delete go routine runs, it is possible that it does not
		// have any quotas to delete. In which case clients would need to wait
		// longer until there is a bucket that has quotas that have expired.
		return &ErrLimiterFull{RetryIn: s.bucketTTL}
	}
	s.items[e.key] = e
	s.addToBucket(e)
	return nil
}

// addToBucket adds the entry to a bucket based on the entry's expiration time.
//
// addToBucket should always be called by a function that first acquires a lock
func (s *expirableStore) addToBucket(e *entry) {
	const op = "rate.(expirableStore).addToBucket"
	if s.mu.TryLock() {
		panic(fmt.Sprintf("%s: called without lock", op))
	}
	e.bucket = (int(e.value.limit.Period/s.bucketTTL) + s.nextBucketToExpire) % s.numberBuckets
	s.buckets[e.bucket].entries[e.key] = e
	if s.buckets[e.bucket].expiresAt.Before(e.value.expiresAt) {
		s.buckets[e.bucket].expiresAt = e.value.expiresAt
	}
}

// emptyExpiredBuckets is called via a go routine. It should run approximately
// once every s.bucketTTL to delete all of the items in the next expired bucket.
func (s *expirableStore) emptyExpiredBucket() {
	s.mu.Lock()

	toExpire := s.nextBucketToExpire
	s.nextBucketToExpire = (s.nextBucketToExpire + 1) % s.numberBuckets

	timeToExpire := time.Until(s.buckets[toExpire].expiresAt)
	// Just in case, check to see if this has run early and there is still some
	// time before the bucket expires. in which case wait until the bucket has
	// expired before deleting.
	if timeToExpire > 0 {
		s.mu.Unlock()
		time.Sleep(timeToExpire)
		s.mu.Lock()
	}
	defer s.mu.Unlock()

	// Get the length of the map prior to deleting entries. While we cannot
	// get the true capacity of the map, it must be at least this length,
	// and deleting the items will not reduce its capacity. So this length
	// will be used to determine if we should re-allocate the map to allow
	// some memory to be released.
	entryCount := len(s.buckets[toExpire].entries)
	for _, delEnt := range s.buckets[toExpire].entries {
		s.removeEntry(delEnt)
	}

	// Only re-allocate if the map grew beyond the initial size.
	if entryCount > bucketSizeThreshold {
		s.buckets[toExpire] = bucket{
			entries: make(map[string]*entry),
		}
	}
	s.usageMetric.Set(float64(len(s.items)))
}

// removeEntry removes the entry from the store and adds the entry back to
// the sync pool.
//
// removeEntry should always be called by a function that first acquires a lock
func (s *expirableStore) removeEntry(e *entry) {
	const op = "rate.(expirableStore).removeEntry"
	if s.mu.TryLock() {
		panic(fmt.Sprintf("%s: called without lock", op))
	}
	delete(s.items, e.key)
	s.removeFromBucket(e)
	s.pool.Put(e)
}

// removeFromBucket removes the entry from the corresponding bucket.
//
// removeFromBucket should always be called by a function that first acquires a lock
func (s *expirableStore) removeFromBucket(e *entry) {
	const op = "rate.(expirableStore).removeFromBucket"
	if s.mu.TryLock() {
		panic(fmt.Sprintf("%s: called without lock", op))
	}
	delete(s.buckets[e.bucket].entries, e.key)
}

// ensure expirableStore can be used as a quotaFetcher
var _ quotaFetcher = (*expirableStore)(nil)
