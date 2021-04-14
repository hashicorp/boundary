package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/internal/scheduler/job/store"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScheduler_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(rw, rw, kmsCache)
	}

	type args struct {
		serverId    string
		jobRepo     job.JobRepoFactory
		looger      hclog.Logger
		runLimit    uint
		runInterval time.Duration
	}
	tests := []struct {
		name        string
		args        args
		opts        []Option
		want        args
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "with-no-server-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.New: missing server id: parameter violation: error #100",
		},
		{
			name: "with-no-job-repo",
			args: args{
				serverId: "test-server",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.New: missing job repo function: parameter violation: error #100",
		},
		{
			name: "with-no-logger",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.New: missing logger: parameter violation: error #100",
		},
		{
			name: "valid",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
				looger:   hclog.L(),
			},
			want: args{
				serverId:    "test-server",
				runLimit:    1,
				runInterval: time.Minute,
			},
		},
		{
			name: "valid-with-interval",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
				looger:   hclog.L(),
			},
			opts: []Option{
				WithRunJobsInterval(time.Hour),
			},
			want: args{
				serverId:    "test-server",
				runLimit:    1,
				runInterval: time.Hour,
			},
		},
		{
			name: "valid-with-limit",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
				looger:   hclog.L(),
			},
			opts: []Option{
				WithRunJobsLimit(20),
			},
			want: args{
				serverId:    "test-server",
				runLimit:    20,
				runInterval: time.Minute,
			},
		},
		{
			name: "valid-with-limit-and-interval",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
				looger:   hclog.L(),
			},
			opts: []Option{
				WithRunJobsInterval(time.Hour),
				WithRunJobsLimit(20),
			},
			want: args{
				serverId:    "test-server",
				runLimit:    20,
				runInterval: time.Hour,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := New(tt.args.serverId, tt.args.jobRepo, tt.args.looger, tt.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Nil(got)
				return
			}
			require.NoError(err)

			assert.Equal(tt.want.serverId, got.serverId)
			assert.Equal(tt.want.runLimit, got.runJobsLimit)
			assert.Equal(tt.want.runInterval, got.runJobsInterval)
			assert.NotNil(got.jobRepoFn)
			assert.NotNil(got.runningJobs)
			assert.NotNil(got.registeredJobs)
		})
	}
}

func TestScheduler_RegisterJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	sched := testScheduler(t, conn, wrapper, server.PrivateId)

	type args struct {
		job  Job
		code string
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "nil-job",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.(Scheduler).RegisterJob: scheduler.validateJob: missing job: parameter violation: error #100",
		},
		{
			name: "missing-job-name",
			args: args{
				job: testJob{},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.(Scheduler).RegisterJob: scheduler.validateJob: missing name: parameter violation: error #100",
		},
		{
			name: "missing-job-description",
			args: args{
				job: testJob{
					name: "name",
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.(Scheduler).RegisterJob: scheduler.validateJob: missing description: parameter violation: error #100",
		},
		{
			name: "missing-job-code",
			args: args{
				job: testJob{
					name:        "name",
					description: "description",
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.(Scheduler).RegisterJob: missing code: parameter violation: error #100",
		},
		{
			name: "valid",
			args: args{
				job: testJob{
					name:        "name",
					description: "description",
				},
				code: "code",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			jobId, err := sched.RegisterJob(context.Background(), tt.args.job, tt.args.code)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Empty(jobId)
				return
			}
			require.NoError(err)
			assert.NotEmpty(jobId)

			j, ok := sched.registeredJobs.Load(jobId)
			require.True(ok)
			require.NotNil(j)
			assert.Equal(tt.args.job, j)

			// Verify job has been persisted
			dbJob := &job.Job{
				Job: &store.Job{
					PrivateId: string(jobId),
				},
			}
			err = rw.LookupById(context.Background(), dbJob)
			require.NoError(err)
			assert.Equal(tt.args.job.Name(), dbJob.Name)
			assert.Equal(tt.args.job.Description(), dbJob.Description)
			assert.Equal(tt.args.code, dbJob.Code)
		})
	}
}

func TestScheduler_UpdateJobNextRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	sched := testScheduler(t, conn, wrapper, server.PrivateId)

	t.Run("missing-job-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		err := sched.UpdateJobNextRun(context.Background(), "", time.Hour)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "Unexpected error %s", err)
		assert.Equal("scheduler.(Scheduler).UpdateJobNextRun: missing job id: parameter violation: error #100", err.Error())
	})
	t.Run("job-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		err := sched.UpdateJobNextRun(context.Background(), "fake-job-id", time.Hour)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("scheduler.(Scheduler).UpdateJobNextRun: job.(Repository).UpdateJobNextRun: db.DoTx: job.(Repository).UpdateJobNextRun: job \"fake-job-id\" does not exist: search issue: error #1100", err.Error())
	})
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		tj := testJob{
			name:        "name",
			description: "description",
		}
		jobId, err := sched.RegisterJob(context.Background(), tj, "code")
		require.NoError(err)

		// get job from repo
		dbJob := &job.Job{
			Job: &store.Job{
				PrivateId: string(jobId),
			},
		}
		err = rw.LookupById(context.Background(), dbJob)
		require.NoError(err)
		previousNextRun := dbJob.NextScheduledRun.Timestamp.GetSeconds()

		err = sched.UpdateJobNextRun(context.Background(), jobId, time.Hour)
		require.NoError(err)

		err = rw.LookupById(context.Background(), dbJob)
		require.NoError(err)
		// Verify job run time in repo is at least 1 hour later than the previous run time
		assert.True(previousNextRun+int64(time.Hour.Seconds()) <= dbJob.NextScheduledRun.Timestamp.GetSeconds())
	})
}

func TestScheduler_StartStop(t *testing.T) {
	assert := assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	sched := testScheduler(t, conn, wrapper, server.PrivateId)

	assert.False(sched.started.Load())
	sched.Start()
	assert.True(sched.started.Load())
	assert.NotNil(sched.baseContext)
	assert.NotNil(sched.baseCancel)

	// verify baseContext
	select {
	case <-sched.baseContext.Done():
		t.Fatal("expected base context to not be done, but it was")
	default:
	}

	// Add some fake running jobs
	context1, cancelFunc1 := context.WithCancel(context.Background())
	context2, cancelFunc2 := context.WithCancel(context.Background())
	sched.l.Lock()
	sched.runningJobs["job1"] = runningJob{runId: "run1", cancelCtx: cancelFunc1}
	sched.runningJobs["job2"] = runningJob{runId: "run2", cancelCtx: cancelFunc2}
	sched.l.Unlock()

	sched.Shutdown()
	assert.False(sched.started.Load())
	sched.l.RLock()
	assert.Len(sched.runningJobs, 0)
	sched.l.RUnlock()

	// verify baseContext has been cancelled
	select {
	case <-sched.baseContext.Done():
	default:
		t.Fatal("expected base context to be cancelled, but it was not")
	}

	// verify both job context's where cancelled
	select {
	case <-context1.Done():
	default:
		t.Fatal("expected context1 to be cancelled, but it was not")
	}
	select {
	case <-context2.Done():
	default:
		t.Fatal("expected context2 to be cancelled, but it was not")
	}
}
