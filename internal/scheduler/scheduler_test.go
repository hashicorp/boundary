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
	t.Parallel()
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
		jobRepo     jobRepoFactory
		logger      hclog.Logger
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
				logger:   hclog.L(),
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
				logger:   hclog.L(),
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
				logger:   hclog.L(),
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
				logger:   hclog.L(),
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
			got, err := New(tt.args.serverId, tt.args.jobRepo, tt.args.logger, tt.opts...)
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
	t.Parallel()
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
	t.Run("multiple-same-job", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tj := testJob{
			name:        "name",
			description: "description",
		}
		jobId, err := sched.RegisterJob(context.Background(), tj, "code")
		require.NoError(err)
		assert.NotEmpty(jobId)

		// Registering the same job/code should not return an error and should return the same jobId
		jobId1, err := sched.RegisterJob(context.Background(), tj, "code")
		require.NoError(err)
		assert.NotEmpty(jobId1)
		assert.Equal(jobId, jobId1)

		// Registering the same job with a different code should return a different jobId
		jobId2, err := sched.RegisterJob(context.Background(), tj, "code1")
		require.NoError(err)
		assert.NotEmpty(jobId2)
		assert.NotEqual(jobId, jobId2)
	})
	t.Run("multiple-schedulers-registering-same-job", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tj := testJob{
			name:        "name",
			description: "description",
		}
		jobId, err := sched.RegisterJob(context.Background(), tj, "code")
		require.NoError(err)
		assert.NotEmpty(jobId)
		_, ok := sched.registeredJobs.Load(jobId)
		assert.True(ok)

		server1 := testController(t, conn, wrapper)
		sched1 := testScheduler(t, conn, wrapper, server1.PrivateId)
		// Verify job is not registered on second scheduler
		_, ok = sched1.registeredJobs.Load(jobId)
		assert.False(ok)

		// Registering job on second scheduler should not return an error and have same id as first scheduler
		jobId1, err := sched1.RegisterJob(context.Background(), tj, "code")
		require.NoError(err)
		assert.Equal(jobId, jobId1)
		_, ok = sched.registeredJobs.Load(jobId)
		assert.True(ok)
	})
}

func TestScheduler_UpdateJobNextRun(t *testing.T) {
	t.Parallel()
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

		// Insert fake job to bypass registration check
		sched.registeredJobs.Store(JobId("fake-job-id"), nil)

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
