// Package permitpool exposes a synchronization primitive for
// limiting the number of concurrent operations. See the Pool
// example for a simple use case.
package permitpool

import "context"

// DefaultParallelOperations is the default number of parallel operations
// allowed by the permit pool.
const DefaultParallelOperations = 128

// Pool is used to limit maximum outstanding requests
type Pool struct {
	sem chan struct{}
}

// New returns a new permit pool with the provided
// number of permits. If permits is less than 1, the
// default number of parallel operations is used.
func New(permits int) *Pool {
	if permits < 1 {
		permits = DefaultParallelOperations
	}
	return &Pool{
		sem: make(chan struct{}, permits),
	}
}

// Acquire returns when a permit has been acquired, or
// if the context is canceled.
func (c *Pool) Acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a permit to the pool
func (c *Pool) Release() {
	<-c.sem
}

// CurrentPermits gets the number of used permits.
// This corresponds to the number of running operations.
func (c *Pool) CurrentPermits() int {
	return len(c.sem)
}
