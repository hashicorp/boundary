// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package scheduler

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/internal/server"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

// TestScheduler creates a mock controller and a new Scheduler attached to that controller id.
// The Scheduler returned should only be used for tests.  The mock controller is not run.
//
// WithRunJobsLimit, WithRunJobsInterval, WithMonitorInterval and WithInterruptThreshold are
// the only valid options.
func TestScheduler(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, opt ...Option) *Scheduler {
	t.Helper()

	ctx := context.Background()
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	serversRepo, err := server.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	iam.TestRepo(t, conn, wrapper)

	id, err := uuid.GenerateUUID()
	require.NoError(t, err)

	controller := server.NewController(fmt.Sprintf("test-server-job%s", id), server.WithAddress("127.0.0.1"))
	_, err = serversRepo.UpsertController(ctx, controller)
	require.NoError(t, err)

	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(ctx, rw, rw, kmsCache)
	}

	s, err := New(ctx, controller.PrivateId, jobRepoFn, opt...)
	require.NoError(t, err)

	return s
}

func testJobFn() (func(ctx context.Context, _ time.Duration) error, chan struct{}, chan struct{}) {
	jobReady := make(chan struct{})
	jobDone := make(chan struct{})
	fn := func(ctx context.Context, _ time.Duration) error {
		jobReady <- struct{}{}

		// Block until context is canceled
		<-ctx.Done()

		jobDone <- struct{}{}
		return nil
	}
	return fn, jobReady, jobDone
}

type testJob struct {
	nextRunIn         time.Duration
	name, description string
	fn                func(context.Context, time.Duration) error
	statusFn          func() JobStatus
}

func (j testJob) Status() JobStatus {
	if j.statusFn == nil {
		return JobStatus{}
	}
	return j.statusFn()
}

func (j testJob) Run(ctx context.Context, statusThreshold time.Duration) error {
	return j.fn(ctx, statusThreshold)
}

func (j testJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return j.nextRunIn, nil
}

func (j testJob) Name() string {
	return j.name
}

func (j testJob) Description() string {
	return j.description
}

func mapLen(sm *sync.Map) int {
	count := 0
	sm.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}
