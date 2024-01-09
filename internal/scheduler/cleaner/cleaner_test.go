// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cleaner_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/scheduler/cleaner"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/stretchr/testify/require"
)

func TestCleanerJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	s := scheduler.TestScheduler(t, conn, wrapper, scheduler.WithMonitorInterval(10*time.Millisecond))
	err := cleaner.RegisterJob(context.Background(), s, rw)
	require.NoError(t, err)
	wg := &sync.WaitGroup{}
	err = s.Start(context.Background(), wg)
	require.NoError(t, err)

	// Trigger some runs, waiting for the cleaner to run
	for i := 0; i < 10; i++ {
		s.RunNow()
		// Wait to allow for the job to finish
		time.Sleep(50 * time.Millisecond)
	}

	var jobRuns []*job.Run
	err = rw.SearchWhere(context.Background(), &jobRuns, "", nil)
	require.NoError(t, err)

	// We should have run 10 times, as long as some of them
	// have been cleaned we should succeed.
	require.True(t, len(jobRuns) < 10, "expected fewer than 10 job_run rows, found %d", len(jobRuns))
}

func TestRegisterJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	s := scheduler.TestScheduler(t, conn, wrapper)

	t.Run("succeeds", func(t *testing.T) {
		err := cleaner.RegisterJob(context.Background(), s, rw)
		require.NoError(t, err)
	})
	t.Run("fails-on-nil-scheduler", func(t *testing.T) {
		err := cleaner.RegisterJob(context.Background(), nil, rw)
		require.Error(t, err)
	})
	t.Run("fails-on-nil-db-writer", func(t *testing.T) {
		err := cleaner.RegisterJob(context.Background(), s, nil)
		require.Error(t, err)
	})
}
