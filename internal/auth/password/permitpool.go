// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-secure-stdlib/permitpool"
)

// resizablePermitPool is a permit pool that can be resized at runtime.
type resizablePermitPool struct {
	pool *permitpool.Pool
	// lock is used to synchronize access to the permit pool
	// This is an RWMutex to allow an unlimited number of readers
	// and a single writer, since allowing a single reader or writer
	// would effectively make the pool useless.
	lock *sync.RWMutex
}

// newResizablePermitPool creates a new resizable permit pool with n permits.
func newResizablePermitPool(n int) *resizablePermitPool {
	return &resizablePermitPool{
		pool: permitpool.New(n),
		lock: &sync.RWMutex{},
	}
}

// SetPermit sets the number of permits available in the pool.
func (r *resizablePermitPool) SetPermits(n int) error {
	const op = "resizablePermitPool.SetPermits"
	if n <= 0 {
		return errors.New(context.Background(), errors.InvalidParameter, op, "n must be greater than 0")
	}
	// Taking a write lock ensures there are no currently acquired permits
	r.lock.Lock()
	defer r.lock.Unlock()
	r.pool = permitpool.New(n)
	return nil
}

// Do executes the provided function with a permit acquired from the pool.
// If the context is canceled while waiting to acquire a permit, an error is returned.
func (r *resizablePermitPool) Do(ctx context.Context, fn func()) error {
	const op = "resizablePermitPool.Do"
	// We need to ensure both the Acquire and Release happen while the read lock is held,
	// so that the pool cannot be resized in between.
	r.lock.RLock()
	defer r.lock.RUnlock()
	if err := r.pool.Acquire(ctx); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to acquire permit"))
	}
	defer r.pool.Release()
	fn()
	return nil
}
