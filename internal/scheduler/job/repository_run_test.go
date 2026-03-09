// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler/job/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_RunJobs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	shortName := testController(t, conn, wrapper, withControllerId("not_10"))

	tests := []struct {
		name         string
		ControllerId string
		job          *Job
		wantRun      bool
		wantErr      bool
		wantErrCode  errors.Code
		wantErrMsg   string
	}{
		{
			name:         "missing-server-id",
			ControllerId: "",
			wantErr:      true,
			wantErrCode:  errors.InvalidParameter,
			wantErrMsg:   "job.(Repository).RunJobs: missing server id: parameter violation: error #100",
		},
		{
			name:         "no-work",
			ControllerId: server.PrivateId,
			wantRun:      false,
			wantErr:      false,
		},
		{
			name:         "valid",
			ControllerId: server.PrivateId,
			job: &Job{
				Job: &store.Job{
					Name:        "valid-test",
					Description: "description",
				},
			},
			wantRun: true,
		},
		{
			name:         "valid-short",
			ControllerId: shortName.PrivateId,
			job: &Job{
				Job: &store.Job{
					Name:        "valid-short-controller-name",
					Description: "description",
				},
			},
			wantRun: true,
		},
		{
			name:         "fake-server-id",
			ControllerId: "fake-server-id",
			job: &Job{
				Job: &store.Job{
					Name:        "fake-server-id-test",
					Description: "description",
				},
			},
			wantErr:     true,
			wantErrCode: errors.NotSpecificIntegrity,
			wantErrMsg:  "job.(Repository).RunJobs: db.DoTx: job.(Repository).RunJobs: db.Query: insert or update on table \"job_run\" violates foreign key constraint \"server_controller_fkey\": integrity violation: error #1003",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.job != nil {
				testJob(t, conn, tt.job.Name, tt.job.Description, wrapper)
			}

			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			got, err := repo.RunJobs(ctx, tt.ControllerId)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)

			if !tt.wantRun {
				assert.Nil(got)
				return
			}

			require.Len(got, 1)
			assert.Equal(tt.job.Name, got[0].JobName)
		})
	}
}

func TestRepository_RunJobsOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	assert, require := assert.New(t), require.New(t)

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	// Regardless of order of adding jobs, fetching work should be based on order of earliest scheduled time
	lastJob := testJob(t, conn, "future", "description", wrapper, WithNextRunIn(-1*time.Hour))
	firstJob := testJob(t, conn, "past", "description", wrapper, WithNextRunIn(-24*time.Hour))
	middleJob := testJob(t, conn, "current", "description", wrapper, WithNextRunIn(-12*time.Hour))

	runs, err := repo.RunJobs(ctx, server.PrivateId)
	require.NoError(err)
	require.Len(runs, 3)

	// We should see the job runs ordered by scheduled time.
	// firstJob > middleJob > lastJob
	assert.Equal(firstJob.Name, runs[0].JobName)
	assert.Equal(firstJob.PluginId, runs[0].JobPluginId)

	assert.Equal(middleJob.Name, runs[1].JobName)
	assert.Equal(middleJob.PluginId, runs[1].JobPluginId)

	assert.Equal(lastJob.Name, runs[2].JobName)
	assert.Equal(lastJob.PluginId, runs[2].JobPluginId)
}

func TestRepository_UpdateProgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "description", wrapper)

	type args struct {
		completed, total, retries int
	}

	tests := []struct {
		name        string
		orig        *Run
		args        args
		want        args
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "no-run-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpdateProgress: missing run id: parameter violation: error #100",
		},
		{
			name: "status-already-interrupted",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Interrupted.string(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).UpdateProgress: db.DoTx: job.(Repository).UpdateProgress: job run was in a final run state: interrupted: integrity violation: error #115",
		},
		{
			name: "status-already-failed",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Failed.string(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).UpdateProgress: db.DoTx: job.(Repository).UpdateProgress: job run was in a final run state: failed: integrity violation: error #115",
		},
		{
			name: "valid-no-changes",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
				},
			},
		},
		{
			name: "valid-update-total",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
				},
			},
			args: args{
				total:   10,
				retries: 1,
			},
			want: args{
				total:   10,
				retries: 1,
			},
		},
		{
			name: "valid-update-completed",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
					TotalCount:   10,
				},
			},
			args: args{
				completed: 10,
				total:     10,
			},
			want: args{
				completed: 10,
				total:     10,
			},
		},
		{
			name: "valid-update-completed-and-total",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
				},
			},
			args: args{
				completed: 10,
				total:     20,
				retries:   1,
			},
			want: args{
				completed: 10,
				total:     20,
				retries:   1,
			},
		},
		{
			name: "invalid-completed-greater-than-total",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
				},
			},
			args: args{
				completed: 10,
			},
			wantErr:     true,
			wantErrCode: errors.CheckConstraint,
			wantErrMsg:  "job.(Repository).UpdateProgress: db.DoTx: job.(Repository).UpdateProgress: db.Query: job_run_completed_count_less_than_equal_to_total_count constraint failed: check constraint violated: integrity violation: error #1000",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			var privateId string
			if tt.orig != nil {
				err = rw.Create(ctx, tt.orig)
				assert.NoError(err)
				assert.Empty(tt.orig.EndTime)
				privateId = tt.orig.PrivateId
			}

			got, err := repo.UpdateProgress(ctx, privateId, tt.args.completed, tt.args.total, tt.args.retries)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())

				if tt.orig != nil {
					// Delete job run so it does not clash with future runs
					_, err = repo.deleteRun(ctx, privateId)
					assert.NoError(err)
				}

				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.Nil(got.EndTime)
			assert.Equal(Running.string(), got.Status)
			assert.Equal(uint32(tt.want.completed), got.CompletedCount)
			assert.Equal(uint32(tt.want.total), got.TotalCount)

			// Delete job run so it does not clash with future runs
			_, err = repo.deleteRun(context.Background(), privateId)
			assert.NoError(err)
		})
	}

	t.Run("job-run-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.UpdateProgress(ctx, "fake-run-id", 0, 0, 0)
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).UpdateProgress: db.DoTx: job.(Repository).UpdateProgress: job run \"fake-run-id\" does not exist: db.LookupById: record not found, search issue: error #1100: dbw.LookupById: record not found", err.Error())
	})
}

func TestRepository_CompleteRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "description", wrapper)

	tests := []struct {
		name        string
		orig        *Run
		nextRunIn   time.Duration
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "no-run-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CompleteRun: missing run id: parameter violation: error #100",
		},
		{
			name: "status-already-interrupted",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Interrupted.string(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).CompleteRun: db.DoTx: job.(Repository).CompleteRun: job run was in a final run state: interrupted: integrity violation: error #115",
		},
		{
			name: "status-already-failed",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Failed.string(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).CompleteRun: db.DoTx: job.(Repository).CompleteRun: job run was in a final run state: failed: integrity violation: error #115",
		},
		{
			name: "valid",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
				},
			},
			nextRunIn: time.Hour,
		},
		{
			name: "valid-with-progress",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			var privateId string
			if tt.orig != nil {
				err = rw.Create(ctx, tt.orig)
				require.NoError(err)
				assert.Empty(tt.orig.EndTime)
				privateId = tt.orig.PrivateId

				r, err := repo.LookupRun(ctx, privateId)
				require.NoError(err)
				require.NotNil(r)
			}

			err = repo.CompleteRun(ctx, privateId, tt.nextRunIn)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())

				if tt.orig != nil {
					// Delete job run so it does not clash with future runs
					_, err = repo.deleteRun(ctx, privateId)
					assert.NoError(err)
				}

				return
			}
			assert.NoError(err)

			updatedJob, err := repo.LookupJob(ctx, tt.orig.JobName)
			assert.NoError(err)
			require.NotNil(updatedJob)

			// The next run is expected to be ~ now + whatever duration was
			// passed into CompleteRun.
			expectedNextRunIn := time.Now().Add(tt.nextRunIn).Round(time.Minute).UTC()
			actualNextRunIn := updatedJob.NextScheduledRun.AsTime().Round(time.Minute).UTC()
			require.EqualValues(expectedNextRunIn, actualNextRunIn)

			// If we can't find the run, it means it was complete.
			r, err := repo.LookupRun(ctx, privateId)
			require.NoError(err)
			require.Nil(r)
		})
	}

	t.Run("job-run-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		err = repo.CompleteRun(ctx, "fake-run-id", time.Hour)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).CompleteRun: db.DoTx: job.(Repository).CompleteRun: job run \"fake-run-id\" does not exist: db.LookupById: record not found, search issue: error #1100: dbw.LookupById: record not found", err.Error())
	})
}

func TestRepository_FailRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "description", wrapper)

	type args struct {
		completed, total, retries int
	}
	tests := []struct {
		name        string
		orig        *Run
		args        args
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "no-run-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).FailRun: missing run id: parameter violation: error #100",
		},
		{
			name: "status-already-interrupted",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Interrupted.string(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).FailRun: db.DoTx: job.(Repository).FailRun: job run was in a final run state: interrupted: integrity violation: error #115",
		},
		{
			name: "status-already-failed",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Failed.string(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).FailRun: db.DoTx: job.(Repository).FailRun: job run was in a final run state: failed: integrity violation: error #115",
		},
		{
			name: "valid",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
				},
			},
		},
		{
			name: "valid-with-progress",
			orig: &Run{
				JobRun: &store.JobRun{
					JobName:      job.Name,
					JobPluginId:  job.PluginId,
					ControllerId: server.PrivateId,
					Status:       Running.string(),
				},
			},
			args: args{completed: 10, total: 20, retries: 5},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			var privateId string
			if tt.orig != nil {
				err = rw.Create(ctx, tt.orig)
				assert.NoError(err)
				assert.Empty(tt.orig.EndTime)
				privateId = tt.orig.PrivateId
			}

			got, err := repo.FailRun(ctx, privateId, tt.args.completed, tt.args.total, tt.args.retries)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())

				if tt.orig != nil {
					// Delete job run so it does not clash with future runs
					_, err = repo.deleteRun(ctx, privateId)
					assert.NoError(err)
				}

				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.NotEmpty(got.EndTime)
			assert.Equal(Failed.string(), got.Status)
			assert.Equal(tt.args.completed, int(got.CompletedCount))
			assert.Equal(tt.args.total, int(got.TotalCount))
			assert.Equal(tt.args.retries, int(got.RetriesCount))

			// Delete job run so it does not clash with future runs
			_, err = repo.deleteRun(context.Background(), privateId)
			assert.NoError(err)
		})
	}

	t.Run("job-run-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.FailRun(ctx, "fake-run-id", 0, 0, 0)
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).FailRun: db.DoTx: job.(Repository).FailRun: job run \"fake-run-id\" does not exist: db.LookupById: record not found, search issue: error #1100: dbw.LookupById: record not found", err.Error())
	})
}

func TestRepository_InterruptRuns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job1 := testJob(t, conn, "job1", "description", wrapper)
	job2 := testJob(t, conn, "job2", "description", wrapper)
	job3 := testJob(t, conn, "job3", "description", wrapper)
	job4 := testJob(t, conn, "job4", "description", wrapper)

	// Each test creates 4 runs with update_times of 1, 3, 5 and 7 hours in the past
	tests := []struct {
		name               string
		threshold          time.Duration
		expectedInterrupts []*Job
	}{
		{
			name:               "with-0-threshold",
			threshold:          0,
			expectedInterrupts: []*Job{job1, job2, job3, job4},
		},
		{
			name:               "threshold-longer-than-all-runs",
			threshold:          24 * time.Hour,
			expectedInterrupts: []*Job{},
		},
		{
			name:               "with-6-hour-threshold",
			threshold:          6 * time.Hour,
			expectedInterrupts: []*Job{job4},
		},
		{
			name:               "with-4-hour-threshold",
			threshold:          4 * time.Hour,
			expectedInterrupts: []*Job{job3, job4},
		},
		{
			name:               "with-2-hour-threshold",
			threshold:          2 * time.Hour,
			expectedInterrupts: []*Job{job2, job3, job4},
		},
		{
			name:               "with-30-minute-threshold",
			threshold:          30 * time.Minute,
			expectedInterrupts: []*Job{job1, job2, job3, job4},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			// Insert test runs with a forced update time
			_, err = testRunWithUpdateTime(conn, job1.PluginId, job1.Name, server.PrivateId, time.Now().Add(-1*time.Hour))
			require.NoError(err)
			_, err = testRunWithUpdateTime(conn, job2.PluginId, job2.Name, server.PrivateId, time.Now().Add(-3*time.Hour))
			require.NoError(err)
			_, err = testRunWithUpdateTime(conn, job3.PluginId, job3.Name, server.PrivateId, time.Now().Add(-5*time.Hour))
			require.NoError(err)
			_, err = testRunWithUpdateTime(conn, job4.PluginId, job4.Name, server.PrivateId, time.Now().Add(-7*time.Hour))
			require.NoError(err)

			runs, err := repo.InterruptRuns(ctx, tt.threshold)
			require.NoError(err)
			assert.Equal(len(runs), len(tt.expectedInterrupts))
			for _, eJob := range tt.expectedInterrupts {
				var gotRun bool
				for _, run := range runs {
					if run.JobName == eJob.Name && run.JobPluginId == eJob.PluginId {
						gotRun = true
						break
					}
				}
				assert.True(gotRun)
			}

			// Interrupt all runs for next test
			_, err = repo.InterruptRuns(ctx, 0)
			assert.NoError(err)
		})
	}
}

func TestRepository_InterruptServerRuns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server1 := testController(t, conn, wrapper)
	server2 := testController(t, conn, wrapper)
	server3 := testController(t, conn, wrapper)
	job1 := testJob(t, conn, "job1", "description", wrapper)
	job2 := testJob(t, conn, "job2", "description", wrapper)
	job3 := testJob(t, conn, "job3", "description", wrapper)

	type args struct {
		ControllerId string
		opts         []Option
		expectedJobs []*Job
	}
	tests := []struct {
		name       string
		runs       []args
		interrupts []args
	}{
		{
			name: "all-runs",
			runs: []args{
				{
					ControllerId: server1.PrivateId,
					expectedJobs: []*Job{job1, job2, job3},
				},
			},
			interrupts: []args{
				{
					expectedJobs: []*Job{job1, job2, job3},
				},
			},
		},
		{
			name: "all-runs-on-single-server-with-server-id",
			runs: []args{
				{
					ControllerId: server2.PrivateId,
					expectedJobs: []*Job{job1, job2, job3},
				},
			},
			interrupts: []args{
				{
					opts:         []Option{WithControllerId(server1.PrivateId)},
					expectedJobs: []*Job{},
				},
				{
					opts:         []Option{WithControllerId(server2.PrivateId)},
					expectedJobs: []*Job{job1, job2, job3},
				},
				{
					opts:         []Option{WithControllerId(server3.PrivateId)},
					expectedJobs: []*Job{},
				},
			},
		},
		{
			name: "no-runs",
			runs: []args{},
			interrupts: []args{
				{
					expectedJobs: []*Job{},
				},
			},
		},
		{
			name: "no-runs-with-server-ids",
			runs: []args{},
			interrupts: []args{
				{
					opts:         []Option{WithControllerId(server1.PrivateId)},
					expectedJobs: []*Job{},
				},
				{
					opts:         []Option{WithControllerId(server2.PrivateId)},
					expectedJobs: []*Job{},
				},
				{
					opts:         []Option{WithControllerId(server3.PrivateId)},
					expectedJobs: []*Job{},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			require.NoError(err)

			for _, r := range tt.runs {
				runs, err := repo.RunJobs(ctx, r.ControllerId)
				require.NoError(err)
				assert.Len(runs, len(r.expectedJobs))
				sort.Slice(runs, func(i, j int) bool { return runs[i].JobName < runs[j].JobName })
				sort.Slice(r.expectedJobs, func(i, j int) bool { return r.expectedJobs[i].Name < r.expectedJobs[j].Name })
				for i := range runs {
					assert.Equal(runs[i].JobName, r.expectedJobs[i].Name)
					assert.Equal(runs[i].JobPluginId, r.expectedJobs[i].PluginId)
					assert.Equal(Running.string(), runs[i].Status)
				}
			}

			for _, interrupt := range tt.interrupts {
				runs, err := repo.InterruptRuns(context.Background(), 0, interrupt.opts...)
				require.NoError(err)
				require.Len(runs, len(interrupt.expectedJobs))
				sort.Slice(runs, func(i, j int) bool { return runs[i].JobName < runs[j].JobName })
				sort.Slice(interrupt.expectedJobs, func(i, j int) bool { return interrupt.expectedJobs[i].Name < interrupt.expectedJobs[j].Name })
				for i := range runs {
					assert.Equal(runs[i].JobName, interrupt.expectedJobs[i].Name)
					assert.Equal(runs[i].JobPluginId, interrupt.expectedJobs[i].PluginId)
					assert.Equal(Interrupted.string(), runs[i].Status)
				}
			}

			// Interrupt any remaining runs for next test
			_, err = repo.InterruptRuns(context.Background(), 0)
			assert.NoError(err)
		})
	}
}

func TestRepository_DuplicateJobRun(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)

	job1 := testJob(t, conn, "job1", "description", wrapper)
	require.NotNil(job1)

	run, err := testRun(conn, job1.PluginId, job1.Name, server.PrivateId)
	require.NoError(err)
	require.NotNil(run)

	// Inserting the same job run should conflict on job name and not create a run
	run, err = testRun(conn, job1.PluginId, job1.Name, server.PrivateId)
	require.Nil(err)
	require.Nil(run)

	// Creating a new job with a different name, the associated run should not conflict with the previous run
	job2 := testJob(t, conn, "job2", "description", wrapper)
	require.NotNil(job1)

	run, err = testRun(conn, job2.PluginId, job2.Name, server.PrivateId)
	require.NoError(err)
	require.NotNil(run)
}

func TestRepository_LookupJobRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "description", wrapper)
	server := testController(t, conn, wrapper)
	run, err := testRun(conn, job.PluginId, job.Name, server.PrivateId)
	require.NoError(t, err)
	require.NotNil(t, run)

	tests := []struct {
		name        string
		in          string
		want        *Run
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "with-no-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).LookupRun: missing run id: parameter violation: error #100",
		},
		{
			name: "with-non-existing-id",
			in:   "fake-run-id",
		},
		{
			name: "with-existing-id",
			in:   run.PrivateId,
			want: run,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupRun(ctx, tt.in)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_deleteJobRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "description", wrapper)
	server := testController(t, conn, wrapper)

	run, err := testRun(conn, job.PluginId, job.Name, server.PrivateId)
	require.NoError(t, err)
	require.NotNil(t, run)

	tests := []struct {
		name        string
		in          string
		want        int
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "With no run id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).deleteRun: missing run id: parameter violation: error #100",
		},
		{
			name: "With non existing job id",
			in:   "fake-run-id",
			want: 0,
		},
		{
			name: "With existing job id",
			in:   run.PrivateId,
			want: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.deleteRun(ctx, tt.in)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Zero(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}
