// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScheduler_New(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(ctx, rw, rw, kmsCache)
	}

	type args struct {
		serverId        string
		jobRepo         jobRepoFactory
		runInterval     time.Duration
		monitorInterval time.Duration
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
			name: "valid",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
			},
			want: args{
				serverId:        "test-server",
				runInterval:     defaultRunJobsInterval,
				monitorInterval: defaultMonitorInterval,
			},
		},
		{
			name: "valid-with-interval",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
			},
			opts: []Option{
				WithRunJobsInterval(time.Hour),
			},
			want: args{
				serverId:        "test-server",
				monitorInterval: defaultMonitorInterval,
				runInterval:     time.Hour,
			},
		},
		{
			name: "valid-with-unlimited",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
			},
			opts: []Option{},
			want: args{
				serverId:        "test-server",
				runInterval:     defaultRunJobsInterval,
				monitorInterval: defaultMonitorInterval,
			},
		},
		{
			name: "valid-with-limit",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
			},
			opts: []Option{},
			want: args{
				serverId:        "test-server",
				runInterval:     defaultRunJobsInterval,
				monitorInterval: defaultMonitorInterval,
			},
		},
		{
			name: "valid-with-monitor",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
			},
			opts: []Option{
				WithMonitorInterval(time.Hour),
			},
			want: args{
				serverId:        "test-server",
				runInterval:     defaultRunJobsInterval,
				monitorInterval: time.Hour,
			},
		},
		{
			name: "valid-with-all",
			args: args{
				serverId: "test-server",
				jobRepo:  jobRepoFn,
			},
			opts: []Option{
				WithRunJobsInterval(time.Hour),
				WithMonitorInterval(2 * time.Hour),
			},
			want: args{
				serverId:        "test-server",
				runInterval:     time.Hour,
				monitorInterval: 2 * time.Hour,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := New(ctx, tt.args.serverId, tt.args.jobRepo, tt.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Nil(got)
				return
			}
			require.NoError(err)

			assert.Equal(tt.want.serverId, got.serverId)
			assert.Equal(tt.want.runInterval, got.runJobsInterval)
			assert.Equal(tt.want.monitorInterval, got.monitorInterval)
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

	sched := TestScheduler(t, conn, wrapper)

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
				name:        "valid",
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
			err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []any{tt.job.Name()})
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
			name:        "multiple-schedulers-registering-same-job",
			description: "description",
		}
		err := sched.RegisterJob(context.Background(), tj)
		require.NoError(err)
		_, ok := sched.registeredJobs.Load(tj.name)
		assert.True(ok)

		sched1 := TestScheduler(t, conn, wrapper)
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

func TestScheduler_UpdateJobNextRunInAtLeast(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	sched := TestScheduler(t, conn, wrapper)

	t.Run("missing-job-name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		err := sched.UpdateJobNextRunInAtLeast(context.Background(), "", time.Hour)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "Unexpected error %s", err)
		assert.Equal("scheduler.(Scheduler).UpdateJobNextRunInAtLeast: missing name: parameter violation: error #100", err.Error())
	})
	t.Run("job-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		// Insert fake job to bypass registration check
		sched.registeredJobs.Store("fake-job-name", nil)

		err := sched.UpdateJobNextRunInAtLeast(context.Background(), "fake-job-name", time.Hour)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("scheduler.(Scheduler).UpdateJobNextRunInAtLeast: job.(Repository).UpdateJobNextRunInAtLeast: db.DoTx: job.(Repository).UpdateJobNextRunInAtLeast: job \"fake-job-name\" does not exist: search issue: error #1100", err.Error())
	})
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		tj := testJob{
			name:        "valid",
			description: "description",
		}
		err := sched.RegisterJob(context.Background(), tj, WithNextRunIn(2*time.Hour))
		require.NoError(err)

		// get job from repo
		var dbJob job.Job
		err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []any{tj.name})
		require.NoError(err)
		previousNextRun := dbJob.NextScheduledRun.AsTime()

		err = sched.UpdateJobNextRunInAtLeast(context.Background(), tj.name, time.Hour)
		require.NoError(err)

		err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []any{tj.name})
		require.NoError(err)
		// Verify job run time in repo is at least 1 hour before than the previous run time
		assert.Equal(previousNextRun.Add(-1*time.Hour).Round(time.Minute), dbJob.NextScheduledRun.AsTime().Round(time.Minute))
	})

	t.Run("next-run-already-sooner", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		tj := testJob{
			name:        "next-run-already-sooner",
			description: "description",
		}
		err := sched.RegisterJob(context.Background(), tj, WithNextRunIn(2*time.Hour))
		require.NoError(err)

		// get job from repo
		var dbJob job.Job
		err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []any{tj.name})
		require.NoError(err)
		previousNextRun := dbJob.NextScheduledRun.AsTime()

		err = sched.UpdateJobNextRunInAtLeast(context.Background(), tj.name, 4*time.Hour)
		require.NoError(err)

		err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []any{tj.name})
		require.NoError(err)
		// Job should not have updated next run time, since its later than the already scheduled time
		assert.Equal(previousNextRun, dbJob.NextScheduledRun.AsTime())

		err = sched.UpdateJobNextRunInAtLeast(context.Background(), tj.name, time.Hour)
		require.NoError(err)

		err = rw.LookupWhere(context.Background(), &dbJob, "name = ?", []any{tj.name})
		require.NoError(err)
		// Verify job run time in repo is at least 1 hour before than the previous run time
		assert.Equal(previousNextRun.Add(-1*time.Hour).Round(time.Minute), dbJob.NextScheduledRun.AsTime().Round(time.Minute))
	})
}

func TestScheduler_Start(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	sched := TestScheduler(t, conn, wrapper)

	tests := []struct {
		name            string
		ctx             context.Context
		wg              *sync.WaitGroup
		wantErr         bool
		wantErrContains string
	}{
		{
			name:            "missing-ctx",
			wg:              &sync.WaitGroup{},
			wantErr:         true,
			wantErrContains: "missing context",
		},
		{
			name:            "missing-waitgroup",
			ctx:             context.Background(),
			wantErr:         true,
			wantErrContains: "missing wait group",
		},

		{
			name: "valid",
			ctx:  context.Background(),
			wg:   &sync.WaitGroup{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := sched.Start(tt.ctx, tt.wg)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}
