// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package scheduler

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchedulerWorkflow(t *testing.T) {
	// do not use t.Parallel() since it relies on the sys eventer
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestSchedulerWorkflow", event.WithEventerConfig(testConfig))
	require.NoError(err)
	sched := TestScheduler(t, conn, wrapper, WithRunJobsInterval(time.Second))

	job1Ch := make(chan error)
	job1Ready := make(chan struct{})
	testDone := make(chan struct{})
	fn1 := func(_ context.Context, _ time.Duration) error {
		select {
		case <-testDone:
			return nil
		case job1Ready <- struct{}{}:
		}
		return <-job1Ch
	}
	tj1 := testJob{name: "name1", description: "desc", fn: fn1, nextRunIn: time.Hour}
	err = sched.RegisterJob(context.Background(), tj1)
	require.NoError(err)

	job2Ch := make(chan error)
	job2Ready := make(chan struct{})
	fn2 := func(_ context.Context, _ time.Duration) error {
		select {
		case <-testDone:
			return nil
		case job2Ready <- struct{}{}:
		}
		return <-job2Ch
	}
	tj2 := testJob{name: "name2", description: "desc", fn: fn2, nextRunIn: time.Hour}
	err = sched.RegisterJob(context.Background(), tj2)
	require.NoError(err)
	baseCtx, baseCnl := context.WithCancel(context.Background())
	defer baseCnl()
	var wg sync.WaitGroup
	err = sched.Start(baseCtx, &wg)
	require.NoError(err)

	// Wait for scheduler to run both jobs
	<-job1Ready
	<-job2Ready

	assert.Equal(mapLen(sched.runningJobs), 2)

	// Fail first job, complete second job
	job1Ch <- fmt.Errorf("failure")
	job2Ch <- nil

	// Scheduler should only try and run job1 again as job2 was successful
	<-job1Ready

	require.Equal(mapLen(sched.runningJobs), 1)

	// Complete job 1
	job1Ch <- nil

	// Update job2 to run again
	err = sched.UpdateJobNextRunInAtLeast(context.Background(), tj2.name, 0)
	require.NoError(err)
	<-job2Ready

	require.Equal(mapLen(sched.runningJobs), 1)

	// Complete job 2
	job2Ch <- nil

	close(testDone)
	close(job1Ch)
	close(job2Ch)
}

func TestSchedulerCancelCtx(t *testing.T) {
	// do not use t.Parallel() since it relies on the sys eventer
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestSchedulerCancelCtx", event.WithEventerConfig(testConfig))
	require.NoError(err)

	sched := TestScheduler(t, conn, wrapper, WithRunJobsInterval(time.Second))

	fn, jobReady, jobDone := testJobFn()
	tj := testJob{name: "name", description: "desc", fn: fn, nextRunIn: time.Hour}
	err = sched.RegisterJob(context.Background(), tj)
	require.NoError(err)

	baseCtx, baseCnl := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer wg.Wait()
	err = sched.Start(baseCtx, &wg)
	require.NoError(err)

	// Wait for scheduler to run job
	<-jobReady

	assert.Equal(mapLen(sched.runningJobs), 1)

	// Yield processor
	runtime.Gosched()

	// Verify job is not done
	select {
	case <-jobDone:
		t.Fatal("expected job to be blocking on context")
	default:
	}

	// Cancel the base context and all job context's should be canceled and exit
	baseCnl()
	<-jobDone
}

func TestSchedulerInterruptedCancelCtx(t *testing.T) {
	// do not use t.Parallel() since it relies on the sys eventer
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestSchedulerInterruptedCancelCtx", event.WithEventerConfig(testConfig))
	require.NoError(err)

	sched := TestScheduler(t, conn, wrapper, WithRunJobsInterval(time.Second), WithMonitorInterval(time.Second))

	fn, job1Ready, job1Done := testJobFn()
	tj1 := testJob{name: "name1", description: "desc", fn: fn, nextRunIn: time.Hour}
	err = sched.RegisterJob(ctx, tj1)
	require.NoError(err)

	fn, job2Ready, job2Done := testJobFn()
	tj2 := testJob{name: "name2", description: "desc", fn: fn, nextRunIn: time.Hour}
	err = sched.RegisterJob(ctx, tj2)
	require.NoError(err)

	baseCtx, baseCnl := context.WithCancel(context.Background())
	defer baseCnl()
	var wg sync.WaitGroup
	wg.Wait()
	err = sched.Start(baseCtx, &wg)
	require.NoError(err)

	// Wait for scheduler to run both job
	<-job1Ready
	<-job2Ready

	require.Equal(mapLen(sched.runningJobs), 2)
	runJob, ok := sched.runningJobs.Load(tj1.name)
	require.True(ok)
	run1Id := runJob.(*runningJob).runId
	runJob, ok = sched.runningJobs.Load(tj2.name)
	require.True(ok)
	run2Id := runJob.(*runningJob).runId

	// Yield processor
	runtime.Gosched()

	// Verify job 1 is not done
	select {
	case <-job1Done:
		t.Fatal("expected job 1 to be blocking on context")
	default:
	}

	// Verify job 2 is not done
	select {
	case <-job2Done:
		t.Fatal("expected job 2 to be blocking on context")
	default:
	}

	// Interrupt job 1 run to cause monitor loop to trigger cancel
	repo, err := job.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	run, err := repo.LookupRun(ctx, run1Id)
	require.NoError(err)
	run.Status = string(job.Interrupted)
	rowsUpdated, err := rw.Update(ctx, run, []string{"Status"}, nil)
	require.NoError(err)
	assert.Equal(1, rowsUpdated)

	// Once monitor cancels context the job should exit
	<-job1Done

	// Yield processor
	runtime.Gosched()

	// Verify job 2 is not done
	select {
	case <-job2Done:
		t.Fatal("expected job 2 to be blocking on context")
	default:
	}

	// Interrupt job 2 run to cause monitor loop to trigger cancel
	repo, err = job.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	run, err = repo.LookupRun(ctx, run2Id)
	require.NoError(err)
	run.Status = string(job.Interrupted)
	rowsUpdated, err = rw.Update(ctx, run, []string{"Status"}, nil)
	require.NoError(err)
	assert.Equal(1, rowsUpdated)

	// Once monitor cancels context the job should exit
	<-job2Done
}

func TestSchedulerJobProgress(t *testing.T) {
	// do not use t.Parallel() since it relies on the sys eventer
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestSchedulerJobProgress", event.WithEventerConfig(testConfig))
	require.NoError(err)

	sched := TestScheduler(t, conn, wrapper, WithRunJobsInterval(time.Second), WithMonitorInterval(time.Second))

	jobReady := make(chan struct{})
	done := make(chan struct{})
	fn := func(ctx context.Context, _ time.Duration) error {
		select {
		case <-done:
			return nil
		case jobReady <- struct{}{}:
		}
		<-ctx.Done()
		return nil
	}

	statusRequest := make(chan struct{})
	jobStatus := make(chan JobStatus)
	status := func() JobStatus {
		select {
		case <-done:
			return JobStatus{}
		default:
		}
		statusRequest <- struct{}{}
		return <-jobStatus
	}
	tj := testJob{name: "name", description: "desc", fn: fn, statusFn: status, nextRunIn: time.Hour}
	err = sched.RegisterJob(context.Background(), tj)
	require.NoError(err)

	baseCtx, baseCnl := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer wg.Wait()
	err = sched.Start(baseCtx, &wg)
	require.NoError(err)

	// Wait for scheduler to run job
	<-jobReady

	require.Equal(mapLen(sched.runningJobs), 1)
	runJob, ok := sched.runningJobs.Load(tj.name)
	require.True(ok)
	runId := runJob.(*runningJob).runId

	// Wait for scheduler to query for job status
	<-statusRequest

	// Send progress to monitor loop to persist
	jobStatus <- JobStatus{Total: 10, Completed: 0, Retries: 1}

	// Wait for scheduler to query for job status before verifying previous results
	<-statusRequest

	repo, err := job.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	run, err := repo.LookupRun(ctx, runId)
	require.NoError(err)
	assert.Equal(string(job.Running), run.Status)
	assert.Equal(uint32(10), run.TotalCount)
	assert.Equal(uint32(0), run.CompletedCount)
	assert.Equal(uint32(1), run.RetriesCount)

	// Send progress to monitor loop to persist
	jobStatus <- JobStatus{Total: 20, Completed: 10}

	// Wait for scheduler to query for job status before verifying previous results
	<-statusRequest

	run, err = repo.LookupRun(context.Background(), runId)
	require.NoError(err)
	assert.Equal(string(job.Running), run.Status)
	assert.Equal(uint32(20), run.TotalCount)
	assert.Equal(uint32(10), run.CompletedCount)

	// Send progress to monitor loop to persist
	jobStatus <- JobStatus{Total: 10, Completed: 20}

	// Wait for scheduler to query for job status before verifying previous results
	<-statusRequest

	// Previous job status was invalid and should not have been persisted
	run, err = repo.LookupRun(context.Background(), runId)
	require.NoError(err)
	assert.Equal(string(job.Running), run.Status)
	assert.Equal(uint32(20), run.TotalCount)
	assert.Equal(uint32(10), run.CompletedCount)

	baseCnl()
	// Close done to bypass future job run / job status requests that will block on channels
	close(done)
	// unblock existing goroutines waiting on channels
	close(jobStatus)
}

func TestSchedulerMonitorLoop(t *testing.T) {
	// do not use t.Parallel() since it relies on the sys eventer
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestSchedulerMonitorLoop", event.WithEventerConfig(testConfig))
	require.NoError(err)

	sched := TestScheduler(t, conn, wrapper, WithInterruptThreshold(time.Second), WithRunJobsInterval(time.Second), WithMonitorInterval(time.Second))

	jobReady := make(chan struct{})
	jobDone := make(chan struct{})
	testDone := make(chan struct{})
	fn := func(ctx context.Context, _ time.Duration) error {
		select {
		case <-testDone:
			return nil
		case jobReady <- struct{}{}:
		}
		<-ctx.Done()
		jobDone <- struct{}{}
		return nil
	}
	tj := testJob{name: "name", description: "desc", fn: fn, nextRunIn: time.Hour}
	err = sched.RegisterJob(context.Background(), tj)
	require.NoError(err)

	baseCtx, baseCnl := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	defer wg.Wait()
	err = sched.Start(baseCtx, &wg)
	require.NoError(err)

	// Wait for scheduler to run job
	<-jobReady

	require.Equal(mapLen(sched.runningJobs), 1)
	runJob, ok := sched.runningJobs.Load(tj.name)
	require.True(ok)
	runId := runJob.(*runningJob).runId

	// Wait for scheduler to interrupt job
	<-jobDone

	repo, err := job.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	run, err := repo.LookupRun(ctx, runId)
	require.NoError(err)
	assert.Equal(string(job.Interrupted), run.Status)
	baseCnl()

	// Close channels to unblock any new jobs that got started
	close(jobDone)
	close(testDone)
}

func TestSchedulerFinalStatusUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestSchedulerFinalStatusUpdate", event.WithEventerConfig(testConfig))
	require.NoError(err)

	sched := TestScheduler(t, conn, wrapper, WithRunJobsInterval(time.Second))

	jobReady := make(chan struct{})
	jobErr := make(chan error)
	testDone := make(chan struct{})
	fn := func(_ context.Context, _ time.Duration) error {
		select {
		case <-testDone:
			return nil
		case jobReady <- struct{}{}:
		}
		return <-jobErr
	}

	jobStatus := make(chan JobStatus)
	status := func() JobStatus {
		return <-jobStatus
	}
	tj := testJob{name: "name", description: "desc", fn: fn, statusFn: status, nextRunIn: time.Hour}
	err = sched.RegisterJob(context.Background(), tj)
	require.NoError(err)

	baseCtx, baseCnl := context.WithCancel(context.Background())
	// call unexported start in order to bypass monitor loop
	go sched.start(baseCtx)

	// Wait for scheduler to run job
	<-jobReady

	require.Equal(mapLen(sched.runningJobs), 1)
	runJob, ok := sched.runningJobs.Load(tj.name)
	require.True(ok)
	runId := runJob.(*runningJob).runId

	// Complete job with error so FailRun is called
	jobErr <- errors.New("scary error")

	// Report status
	jobStatus <- JobStatus{Total: 10, Completed: 10}

	repo, err := job.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)

	run := waitForRunStatus(t, repo, runId, job.Failed)
	assert.Equal(uint32(10), run.TotalCount)
	assert.Equal(uint32(10), run.CompletedCount)

	// Wait for scheduler to run job again
	<-jobReady

	require.Equal(mapLen(sched.runningJobs), 1)
	runJob, ok = sched.runningJobs.Load(tj.name)
	require.True(ok)
	runId = runJob.(*runningJob).runId

	// Complete job without error so CompleteRun is called
	completeFn := waitForRunComplete(t, sched, repo, runId, tj.name)
	jobErr <- nil
	completeFn()

	baseCnl()
	close(testDone)
	close(jobErr)
	close(jobStatus)
}

func TestSchedulerRunNow(t *testing.T) {
	// do not use t.Parallel() since it relies on the sys eventer
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestSchedulerWorkflow", event.WithEventerConfig(testConfig))
	require.NoError(err)

	// Create test scheduler that only runs jobs every hour
	sched := TestScheduler(t, conn, wrapper, WithRunJobsInterval(time.Hour))

	jobCh := make(chan struct{})
	jobReady := make(chan struct{})
	testDone := make(chan struct{})
	fn := func(_ context.Context, _ time.Duration) error {
		select {
		case <-testDone:
			return nil
		case jobReady <- struct{}{}:
		}
		<-jobCh
		return nil
	}
	tj := testJob{name: "name", description: "desc", fn: fn, nextRunIn: time.Hour}
	err = sched.RegisterJob(context.Background(), tj)
	require.NoError(err)

	baseCtx, baseCnl := context.WithCancel(ctx)
	defer baseCnl()
	var wg sync.WaitGroup
	err = sched.Start(baseCtx, &wg)
	require.NoError(err)

	// Wait for scheduler to run job
	<-jobReady
	require.Equal(mapLen(sched.runningJobs), 1)

	runJob, ok := sched.runningJobs.Load(tj.name)
	require.True(ok)
	runId := runJob.(*runningJob).runId

	repo, err := job.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)

	// Complete job
	completeFn := waitForRunComplete(t, sched, repo, runId, tj.name)
	jobCh <- struct{}{}
	completeFn()

	// Update job to run immediately once scheduling loop is called
	err = sched.UpdateJobNextRunInAtLeast(context.Background(), tj.name, 0)
	require.NoError(err)

	// Verify no job is not running
	select {
	case <-jobReady:
		t.Fatal("expected not job to be running")
	default:
	}

	// Trigger scheduling loop
	sched.RunNow()

	// Wait for scheduler to run job
	<-jobReady
	require.Equal(mapLen(sched.runningJobs), 1)

	runJob, ok = sched.runningJobs.Load(tj.name)
	require.True(ok)
	runId = runJob.(*runningJob).runId

	// Complete job
	completeFn = waitForRunComplete(t, sched, repo, runId, tj.name)
	jobCh <- struct{}{}
	completeFn()

	// Update job to run again with RunNow option
	err = sched.UpdateJobNextRunInAtLeast(context.Background(), tj.name, 0, WithRunNow(true))
	require.NoError(err)

	// Wait for scheduler to run job
	<-jobReady
	require.Equal(mapLen(sched.runningJobs), 1)

	// Complete job
	jobCh <- struct{}{}

	// Cleanup tests
	close(testDone)
	close(jobCh)
}

func waitForRunComplete(t *testing.T, sched *Scheduler, repo *job.Repository, runId, jobName string) func() {
	r, err := repo.LookupRun(context.Background(), runId)
	require.NoError(t, err)
	require.EqualValues(t, job.Running, r.Status)

	return func() {
		timeout := time.NewTimer(5 * time.Second)
		for {
			select {
			case <-timeout.C:
				t.Fatal(fmt.Errorf("timed out waiting for job run %q to be completed", runId))
			case <-time.After(100 * time.Millisecond):
			}

			// A run is complete when we don't find it in the scheduler's
			// running jobs list and also not in the job_run table.
			_, ok := sched.runningJobs.Load(jobName)
			if !ok {
				r, err = repo.LookupRun(context.Background(), runId)
				require.Nil(t, r)
				require.Nil(t, err)
				break
			}
		}
	}
}

func waitForRunStatus(t *testing.T, repo *job.Repository, runId string, status job.Status) *job.Run {
	t.Helper()
	var run *job.Run

	// Fail test if waiting for run status change takes longer than 5 seconds
	timeout := time.NewTimer(5 * time.Second)
	for {
		select {
		case <-timeout.C:
			t.Fatal(fmt.Errorf("timed out waiting for job run %v to reach status: %v", runId, status))
		case <-time.After(100 * time.Millisecond):
		}

		var err error
		run, err = repo.LookupRun(context.Background(), runId)
		require.NoError(t, err)
		if run.Status == string(status) {
			break
		}
	}

	return run
}
