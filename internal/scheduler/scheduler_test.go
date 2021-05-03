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

	tests := []struct {
		name        string
		job         Job
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
			name:        "missing-job-name",
			job:         testJob{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.(Scheduler).RegisterJob: scheduler.validateJob: missing name: parameter violation: error #100",
		},
		{
			name: "missing-job-description",
			job: testJob{
				name: "name",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "scheduler.(Scheduler).RegisterJob: scheduler.validateJob: missing description: parameter violation: error #100",
		},
		{
			name: "valid",
			job: testJob{
				name:        "name",
				description: "description",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := sched.RegisterJob(context.Background(), tt.job)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)

			j, ok := sched.registeredJobs.Load(tt.job.Name())
			require.True(ok)
			require.NotNil(j)
			assert.Equal(tt.job, j)

			// Verify job has been persisted
			var dbJob job.Job
			err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []interface{}{tt.job.Name()})
			require.NoError(err)
			require.NotNil(dbJob)
			assert.Equal(tt.job.Name(), dbJob.Name)
			assert.Equal(tt.job.Description(), dbJob.Description)
		})
	}
	t.Run("multiple-same-job", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tj := testJob{
			name:        "multiple-same-job",
			description: "description",
		}

		// Job should not be registered
		_, ok := sched.registeredJobs.Load(tj.name)
		assert.False(ok)

		err := sched.RegisterJob(context.Background(), tj)
		require.NoError(err)

		// Job should now be registered
		_, ok = sched.registeredJobs.Load(tj.name)
		assert.True(ok)

		// Registering the same job should not return an error
		err = sched.RegisterJob(context.Background(), tj)
		require.NoError(err)

		// Job should still be registered
		_, ok = sched.registeredJobs.Load(tj.name)
		assert.True(ok)
	})
	t.Run("multiple-schedulers-registering-same-job", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		tj := testJob{
			name:        "name",
			description: "description",
		}
		err := sched.RegisterJob(context.Background(), tj)
		require.NoError(err)
		_, ok := sched.registeredJobs.Load(tj.name)
		assert.True(ok)

		server1 := testController(t, conn, wrapper)
		sched1 := testScheduler(t, conn, wrapper, server1.PrivateId)
		// Verify job is not registered on second scheduler
		_, ok = sched1.registeredJobs.Load(tj.name)
		assert.False(ok)

		// Registering job on second scheduler should not return an error and should be registered
		err = sched1.RegisterJob(context.Background(), tj)
		require.NoError(err)
		_, ok = sched.registeredJobs.Load(tj.name)
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

	t.Run("missing-job-name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		err := sched.UpdateJobNextRun(context.Background(), "", time.Hour)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "Unexpected error %s", err)
		assert.Equal("scheduler.(Scheduler).UpdateJobNextRun: missing name: parameter violation: error #100", err.Error())
	})
	t.Run("job-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		// Insert fake job to bypass registration check
		sched.registeredJobs.Store("fake-job-name", nil)

		err := sched.UpdateJobNextRun(context.Background(), "fake-job-name", time.Hour)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("scheduler.(Scheduler).UpdateJobNextRun: job.(Repository).UpdateJobNextRun: db.DoTx: job.(Repository).UpdateJobNextRun: job \"fake-job-name\" does not exist: search issue: error #1100", err.Error())
	})
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		tj := testJob{
			name:        "name",
			description: "description",
		}
		err := sched.RegisterJob(context.Background(), tj)
		require.NoError(err)

		// get job from repo
		var dbJob job.Job
		err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []interface{}{tj.name})
		require.NoError(err)
		previousNextRun := dbJob.NextScheduledRun.Timestamp.GetSeconds()

		err = sched.UpdateJobNextRun(context.Background(), tj.name, time.Hour)
		require.NoError(err)

		err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []interface{}{tj.name})
		require.NoError(err)
		// Verify job run time in repo is at least 1 hour later than the previous run time
		assert.True(previousNextRun+int64(time.Hour.Seconds()) <= dbJob.NextScheduledRun.Timestamp.GetSeconds())
	})
}
