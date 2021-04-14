package scheduler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchedulerWorkflow(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	sched := testScheduler(t, conn, wrapper, server.PrivateId, WithRunJobsLimit(10), WithRunJobsInterval(time.Second))

	job1Ch := make(chan error)
	job1Ready := make(chan struct{})
	fn1 := func(_ context.Context) error {
		job1Ready <- struct{}{}
		return <-job1Ch
	}
	tj1 := testJob{name: "name", description: "desc", fn: fn1, nextRunIn: time.Hour}
	_, err := sched.RegisterJob(context.Background(), tj1, "code1")
	require.NoError(err)

	job2Ch := make(chan error)
	job2Ready := make(chan struct{})
	fn2 := func(_ context.Context) error {
		job2Ready <- struct{}{}
		return <-job2Ch
	}
	tj2 := testJob{name: "name", description: "desc", fn: fn2, nextRunIn: time.Hour}
	job2Id, err := sched.RegisterJob(context.Background(), tj2, "code2")
	require.NoError(err)

	sched.Start()

	// Wait for scheduler to run both jobs
	<-job1Ready
	<-job2Ready

	sched.l.RLock()
	assert.Len(sched.runningJobs, 2)
	sched.l.RUnlock()

	// Fail first job, complete second job
	job1Ch <- fmt.Errorf("failure")
	job2Ch <- nil

	// Scheduler should only try and run job1 again as job2 was successful
	<-job1Ready

	sched.l.RLock()
	assert.Len(sched.runningJobs, 1)
	sched.l.RUnlock()

	// Complete job 1
	job1Ch <- nil

	// Update job2 to run again
	err = sched.UpdateJobNextRun(context.Background(), job2Id, 0)
	require.NoError(err)
	<-job2Ready

	sched.l.RLock()
	assert.Len(sched.runningJobs, 1)
	sched.l.RUnlock()

	// Complete job 2
	job2Ch <- nil

	sched.Shutdown()
}

func TestSchedulerCancelCtx(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	sched := testScheduler(t, conn, wrapper, server.PrivateId, WithRunJobsLimit(10), WithRunJobsInterval(time.Second))

	jobReady := make(chan struct{})
	jobDone := make(chan struct{})
	fn := func(ctx context.Context) error {
		jobReady <- struct{}{}

		// Block until context is cancelled
		<-ctx.Done()

		jobDone <- struct{}{}
		return nil
	}
	tj := testJob{name: "name", description: "desc", fn: fn, nextRunIn: time.Hour}
	_, err := sched.RegisterJob(context.Background(), tj, "code2")
	require.NoError(err)

	sched.Start()

	// Wait for scheduler to run job
	<-jobReady

	sched.l.RLock()
	assert.Len(sched.runningJobs, 1)
	sched.l.RUnlock()

	// Verify job is not done
	select {
	case <-jobDone:
		t.Fatal("expected job to be blocking on context")
	default:
	}

	sched.Shutdown()
	// Now that sched is shutdown all job context's should get cancelled
	<-jobDone
}
