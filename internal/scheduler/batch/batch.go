// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

/*
Package batch implements a batch processor for jobs that update or delete
multiple rows in the database using a single SQL UPDATE or DELETE
statement.

It defines a type, [Batch], which is used by a job to execute a SQL
statement in batches. SQL commands are executed in batches by providing an
[Exec] function that executes a SQL statement, which must contain a
parameterized LIMIT clause, and returns the number of rows affected by the
query or an error if the query failed. Batch adjusts the batch size in an
effort to get the query execution time close to the [Config.Target]
duration. When the batch size is adjusted, [Store] is called. Jobs using
the batch processor should persist this value and use it as the starting
batch size in subsequent calls to Batch.

See session.deleteTerminatedJob for an example of how to use the batch
processor.

# SQL

The SQL LIMIT clause can only be used in query statements. It cannot be
used directly in a DELETE or UPDATE statement. Instead, a subquery or CTE
must be used to limit the number of rows affected by the query.

Here is an example SQL DELETE statement that uses a subquery with a LIMIT
clause:

	delete
	  from alias_target_deleted
	 where public_id in (
		 select public_id
		   from alias_target_deleted
		  where delete_time < @delete_time
		  limit @batch_size
	 );
*/
package batch

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
)

const (
	DefaultStatusThreshold = 5 * time.Minute
	DefaultTarget          = 1 * time.Second
)

const (
	DefaultSize = 5000
	DefaultMin  = 10
	DefaultMax  = 10000
)

// Exec is the function type used for executing the batch query. An Exec
// function must return the number of rows affected by the query or an
// error if the query failed.
type Exec func(ctx context.Context, batchSize int) (rowCount int, err error)

// Store is the function type used for storing the batch size in the
// database. A Store function must return an error if the store failed.
type Store func(ctx context.Context, batchSize int) error

// Config is a structure used to configure a [Batch].
type Config struct {
	// Size is the initial batch size.
	//
	// If Size is less than 1, the initial batch size will be set to
	// DefaultSize.
	//
	// If Size is less than Min, the initial batch size will be set to Min.
	//
	// If Size is greater than Max, the initial batch size will be set to
	// Max.
	Size int

	// Min and Max are the minimum and maximum batch sizes allowed. The
	// batch size will be clamped to the range [Min, Max].
	//
	// If Min is less than 1, it will be set to DefaultMin.
	//
	// If Max is less than or equal to Min, it will be set to DefaultMax.
	Min int
	Max int

	// TotalToComplete is the total number of rows to be processed by the
	// job. This is reported in the JobStatus returned by the Status
	// method.
	TotalToComplete int

	// StatusThreshold is the amount of time the job has to return a
	// JobStatus with values different from the previous JobStatus. If a
	// call to Exec approaches this threshold, Batch will interrupt the
	// call to Exec, reduce the batch size, and call Exec again. It will
	// also increment the Retries value reported in the Status method.
	//
	// If StatusThreshold is less than or equal to zero, it will be set to
	// DefaultStatusThreshold.
	StatusThreshold time.Duration

	// Target is the target duration for the query to run in. The batch
	// size will be adjusted to keep the query duration within the target
	// range.
	//
	// If Target is less than or equal to zero, it will be set to
	// DefaultTarget.
	//
	// If Target is greater than or equal to StatusThreshold, it will be
	// set to StatusThreshold - 5ms.
	Target time.Duration

	// Exec is called to execute the query. Exec is called by the Run
	// method in a loop until the row count returned by Exec is less than
	// the current batch size or Exec returns an error other than
	// context.DeadlineExceeded. The configuration must supply this
	// callback for batch to succeed.
	//
	// If Exec returns a context.DeadlineExceeded error, the batch size
	// will be reduced, the Retries value reported in the Status method
	// will be incremented, and then Exec will be called again.
	//
	// If Exec returns an error other than context.DeadlineExceeded, the
	// batch size will not be changed and the Run method will exit
	// returning the error.
	Exec Exec

	// Store, if not nil, is called when the batch size has changed and the
	// new batch size should be stored in the database. If Store returns an
	// error, the Run method will exit and return with the error.
	Store Store
}

func (c *Config) size() int {
	switch {
	case c.Size < 1:
		return DefaultSize
	case c.Size < c.min():
		return c.min()
	case c.Size > c.max():
		return c.max()
	}
	return c.Size
}

func (c *Config) min() int {
	if c.Min < 1 {
		return DefaultMin
	}
	return c.Min
}

func (c *Config) max() int {
	if c.Max <= c.Min {
		return DefaultMax
	}
	return c.Max
}

// Arbitrary constants
const (
	statusThresholdBuffer = 250 * time.Millisecond

	// both ranges are a percentage of the target duration
	lowerRange = 10
	upperRange = 10
)

func (c *Config) statusThreshold() time.Duration {
	if c.StatusThreshold <= 0 {
		return DefaultStatusThreshold - statusThresholdBuffer
	}
	return c.StatusThreshold - statusThresholdBuffer
}

func (c *Config) target() time.Duration {
	switch {
	case c.Target <= 0:
		return DefaultTarget
	case c.Target >= c.statusThreshold():
		return c.statusThreshold()
	}
	return c.Target
}

func (c *Config) targetRange() (lower time.Duration, upper time.Duration) {
	target := c.target()
	return target - (target / lowerRange), target + (target / upperRange)
}

func (c *Config) store() Store {
	if c.Store == nil {
		return func(_ context.Context, _ int) error { return nil }
	}
	return c.Store
}

func (c *Config) clone() *Config {
	if c == nil {
		return nil
	}
	return &Config{
		Size:            c.Size,
		Min:             c.Min,
		Max:             c.Max,
		TotalToComplete: c.TotalToComplete,
		StatusThreshold: c.StatusThreshold,
		Target:          c.Target,
		Exec:            c.Exec,
		Store:           c.Store,
	}
}

// Batch is a batch job processor for SQL jobs that update or delete
// multiple rows in the database using a single SQL UPDATE or DELETE
// statement.
type Batch struct {
	c *Config

	slowExecutions int
	fastExecutions int

	mu             sync.Mutex
	retries        int
	totalCompleted int
}

// New creates a [Batch] that uses the given configuration to execute a SQL
// job in batches. An error is returned if c contains a nil Exec.
func New(ctx context.Context, c *Config) (*Batch, error) {
	const op = "batch.New"
	switch {
	case c == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil Config")
	case c.Exec == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil Exec")
	}
	return &Batch{
		c: c.clone(),
	}, nil
}

// Status reports the job’s current status.
func (b *Batch) Status() scheduler.JobStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return scheduler.JobStatus{
		Completed: b.totalCompleted,
		Total:     b.c.TotalToComplete,
		Retries:   b.retries,
	}
}

// Run runs the batch processor. It calls the [Exec] function in a loop
// until the row count returned by Exec is less than the current batch size
// or Exec returns an error other than context.DeadlineExceeded.
//
// Each call to Run resets the values returned in [Batch.Status].
func (b *Batch) Run(ctx context.Context) error {
	const op = "batch.Run"
	b.reset()

	for {
		count, runDuration, err := b.run(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				if err := b.timedOut(ctx); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				continue
			}
			return errors.Wrap(ctx, err, op)
		}

		b.successful(count)

		// batch is not complete
		if count == b.c.size() {
			if err := b.adjustSize(ctx, runDuration); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			continue
		}

		// batch is complete
		return nil
	}
}

func (b *Batch) run(ctx context.Context) (int, time.Duration, error) {
	queryCtx, cancel := context.WithTimeout(ctx, b.c.statusThreshold())
	defer cancel()
	start := time.Now()
	n, err := b.c.Exec(queryCtx, b.c.size())
	return n, time.Since(start), err
}

func (b *Batch) reset() {
	b.mu.Lock()
	b.retries = 0
	b.totalCompleted = 0
	b.mu.Unlock()
	b.fastExecutions = 0
	b.slowExecutions = 0
}

func (b *Batch) timedOut(ctx context.Context) error {
	b.mu.Lock()
	b.retries++
	b.mu.Unlock()
	return b.c.exponentialDecrease(ctx, b.retries)
}

func (b *Batch) successful(rowCount int) {
	b.mu.Lock()
	b.totalCompleted += rowCount
	b.mu.Unlock()
}

func (b *Batch) adjustSize(ctx context.Context, runDuration time.Duration) error {
	lower, upper := b.c.targetRange()

	switch {
	case runDuration < lower: // too fast
		// increase the batch size to go slower
		b.fastExecutions++
		b.slowExecutions = 0
		return b.c.linearIncrease(ctx, b.fastExecutions)
	case runDuration > upper: // too slow
		// decrease the batch size to go faster
		b.slowExecutions++
		b.fastExecutions = 0
		return b.c.linearDecrease(ctx, b.slowExecutions)
	}

	// within target range so reset the counters
	b.fastExecutions = 0
	b.slowExecutions = 0
	return nil
}

func (c *Config) exponentialDecrease(ctx context.Context, attempt int) error {
	if attempt < 1 {
		attempt = 1
	}
	newSize := (c.size() / (1 << uint(attempt))) - c.jitter()
	return c.setSize(ctx, newSize)
}

func (c *Config) linearIncrease(ctx context.Context, attempt int) error {
	if attempt < 1 {
		attempt = 1
	}
	newSize := c.size() + (c.size() / 10 * attempt) + c.jitter()
	return c.setSize(ctx, newSize)
}

func (c *Config) linearDecrease(ctx context.Context, attempt int) error {
	if attempt < 1 {
		attempt = 1
	}
	newSize := c.size() - (c.size() / 10 * attempt) - c.jitter()
	return c.setSize(ctx, newSize)
}

// jitter returns a random number between 0 and 10% of the current batch
// size.
func (c *Config) jitter() int {
	return rand.N(c.size() / 10)
}

// setSize sets the batch size to newSize and calls Store if newSize is
// different from the current size. If newSize is less than Min, the batch
// size will be set to Min. If newSize is greater than Max, the batch size
// will be set to Max. If Store returns an error, it will be returned by
// setSize.
func (c *Config) setSize(ctx context.Context, newSize int) error {
	currentSize := c.Size
	if newSize == currentSize {
		return nil
	}
	switch {
	case newSize < c.min():
		newSize = c.min()
	case newSize > c.max():
		newSize = c.max()
	}
	if newSize != currentSize {
		c.Size = newSize
		return c.store()(ctx, newSize)
	}
	return nil
}
