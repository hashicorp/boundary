package job

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/job/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_RunJobs(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)

	tests := []struct {
		name        string
		serverId    string
		job         *Job
		wantRun     bool
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "missing-server-id",
			serverId:    "",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).RunJobs: missing server id: parameter violation: error #100",
		},
		{
			name:     "no-work",
			serverId: server.PrivateId,
			wantRun:  false,
			wantErr:  false,
		},
		{
			name:     "valid",
			serverId: server.PrivateId,
			job: &Job{
				Job: &store.Job{
					Name:        "valid-test",
					Code:        "code",
					Description: "description",
				},
			},
			wantRun: true,
		},
		{
			name:     "fake-server-id",
			serverId: "fake-server-id",
			job: &Job{
				Job: &store.Job{
					Name:        "fake-server-id-test",
					Code:        "code",
					Description: "description",
				},
			},
			wantErr:     true,
			wantErrCode: errors.NotSpecificIntegrity,
			wantErrMsg:  "job.(Repository).RunJobs: db.DoTx: job.(Repository).RunJobs: insert or update on table \"job_run\" violates foreign key constraint \"server_fkey\": integrity violation: error #1003",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var jId string
			if tt.job != nil {
				job := testJob(t, conn, tt.job.Name, tt.job.Code, tt.job.Description)
				jId = job.PrivateId
			}

			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			got, err := repo.RunJobs(context.Background(), tt.serverId)
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
			assert.Equal(jId, got[0].JobId)
		})
	}
}

func TestRepository_RunJobs_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	numJobs := 10
	server := testController(t, conn, wrapper)

	tests := []struct {
		name    string
		opts    []Option
		wantLen int
	}{
		{
			name:    "with-more-than-available",
			opts:    []Option{WithRunJobsLimit(uint(numJobs * 2))},
			wantLen: numJobs,
		},
		{
			name:    "with-no-option",
			wantLen: defaultRunJobsLimit,
		},
		{
			name:    "with-limit",
			opts:    []Option{WithRunJobsLimit(3)},
			wantLen: 3,
		},
		{
			name:    "with-zero-limit",
			opts:    []Option{WithRunJobsLimit(0)},
			wantLen: defaultRunJobsLimit,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			for i := 0; i < numJobs; i++ {
				testJob(t, conn, tt.name, fmt.Sprintf("%d", i), "description")
			}

			got, err := repo.RunJobs(context.Background(), server.PrivateId, tt.opts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_RunJobsOrder(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	assert, require := assert.New(t), require.New(t)

	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	// Regardless of order of adding jobs, fetching work should be based on order of earliest scheduled time
	lastJob := testJob(t, conn, "future", "code", "description", WithNextRunAt(time.Now().Add(-1*time.Hour)))
	firstJob := testJob(t, conn, "past", "code", "description", WithNextRunAt(time.Now().Add(-24*time.Hour)))
	middleJob := testJob(t, conn, "current", "code", "description", WithNextRunAt(time.Now().Add(-12*time.Hour)))

	runs, err := repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	require.Len(runs, 1)
	run := runs[0]
	assert.Equal(run.JobId, firstJob.PrivateId)

	// End first job with time between last and middle
	_, err = repo.CompleteRun(context.Background(), run.PrivateId, time.Now().Add(-6*time.Hour))
	require.NoError(err)

	runs, err = repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	require.Len(runs, 1)
	run = runs[0]
	assert.Equal(run.JobId, middleJob.PrivateId)

	// firstJob should be up again, as it is scheduled before lastJob
	runs, err = repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	require.Len(runs, 1)
	run = runs[0]
	assert.Equal(run.JobId, firstJob.PrivateId)

	runs, err = repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	require.Len(runs, 1)
	run = runs[0]
	assert.Equal(run.JobId, lastJob.PrivateId)

	// All jobs are running no work should be returned
	runs, err = repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	require.Len(runs, 0)
}

func TestRepository_UpdateProgress(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "code", "description")

	type args struct {
		completed, total int
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
			name: "status-already-final",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Interrupted.String(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).UpdateProgress: db.DoTx: job.(Repository).UpdateProgress: job run is already in a final run state: integrity violation: error #115",
		},
		{
			name: "valid-no-changes",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
		},
		{
			name: "valid-update-total",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			args: args{
				total: 10,
			},
			want: args{
				total: 10,
			},
		},
		{
			name: "valid-update-completed",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:      job.PrivateId,
					ServerId:   server.PrivateId,
					Status:     Running.String(),
					TotalCount: 10,
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
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			args: args{
				completed: 10,
				total:     20,
			},
			want: args{
				completed: 10,
				total:     20,
			},
		},
		{
			name: "invalid-completed-greater-than-total",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			args: args{
				completed: 10,
			},
			wantErr:     true,
			wantErrCode: errors.CheckConstraint,
			wantErrMsg:  "job.(Repository).UpdateProgress: db.DoTx: job.(Repository).UpdateProgress: job_run_completed_count_less_than_equal_to_total_count constraint failed: check constraint violated: integrity violation: error #1000",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			var privateId string
			if tt.orig != nil {
				err = rw.Create(context.Background(), tt.orig)
				assert.NoError(err)
				assert.Empty(tt.orig.EndTime)
				privateId = tt.orig.PrivateId
			}

			got, err := repo.UpdateProgress(context.Background(), privateId, tt.args.completed, tt.args.total)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())

				if tt.orig != nil {
					// Delete job run so it does not clash with future runs
					_, err = repo.deleteRun(context.Background(), privateId)
					assert.NoError(err)
				}

				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.Nil(got.EndTime)
			assert.Equal(Running.String(), got.Status)
			assert.Equal(uint32(tt.want.completed), got.CompletedCount)
			assert.Equal(uint32(tt.want.total), got.TotalCount)

			// Delete job run so it does not clash with future runs
			_, err = repo.deleteRun(context.Background(), privateId)
			assert.NoError(err)

			// Verify Run has oplog entry
			assert.NoError(db.TestVerifyOplog(t, rw, privateId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second), db.WithResourcePrivateId(true)))
		})
	}

	t.Run("job-run-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.UpdateProgress(context.Background(), "fake-run-id", 0, 0)
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).UpdateProgress: run \"fake-run-id\" does not exist: db.LookupById: record not found, search issue: error #1100", err.Error())
	})
}

func TestRepository_CompleteRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "code", "description")

	futureTime := time.Now().Add(time.Hour)

	tests := []struct {
		name             string
		orig             *Run
		nextScheduledRun time.Time
		wantErr          bool
		wantErrCode      errors.Code
		wantErrMsg       string
	}{
		{
			name:        "no-run-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CompleteRun: missing run id: parameter violation: error #100",
		},
		{
			name: "invalid-next-run",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CompleteRun: missing next scheduled run: parameter violation: error #100",
		},
		{
			name: "status-already-final",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Interrupted.String(),
				},
			},
			nextScheduledRun: futureTime,
			wantErr:          true,
			wantErrCode:      errors.InvalidJobRunState,
			wantErrMsg:       "job.(Repository).CompleteRun: db.DoTx: job.(Repository).CompleteRun: job run is already in a final run state: integrity violation: error #115",
		},
		{
			name: "valid",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			nextScheduledRun: futureTime,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			var privateId string
			if tt.orig != nil {
				err = rw.Create(context.Background(), tt.orig)
				assert.NoError(err)
				assert.Empty(tt.orig.EndTime)
				privateId = tt.orig.PrivateId
			}

			got, err := repo.CompleteRun(context.Background(), privateId, tt.nextScheduledRun)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())

				if tt.orig != nil {
					// Delete job run so it does not clash with future runs
					_, err = repo.deleteRun(context.Background(), privateId)
					assert.NoError(err)
				}

				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.NotEmpty(got.EndTime)
			assert.Equal(Completed.String(), got.Status)

			updatedJob, err := repo.LookupJob(context.Background(), tt.orig.JobId)
			assert.NoError(err)
			require.NotNil(updatedJob)
			assert.Equal(tt.nextScheduledRun.Unix(), updatedJob.NextScheduledRun.Timestamp.GetSeconds())

			// Delete job run so it does not clash with future runs
			_, err = repo.deleteRun(context.Background(), privateId)
			assert.NoError(err)

			// Verify Run has oplog entry
			assert.NoError(db.TestVerifyOplog(t, rw, privateId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second), db.WithResourcePrivateId(true)))

			// Verify Job has oplog entry
			assert.NoError(db.TestVerifyOplog(t, rw, job.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second), db.WithResourcePrivateId(true)))
		})
	}

	t.Run("job-run-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.CompleteRun(context.Background(), "fake-run-id", futureTime)
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).CompleteRun: run \"fake-run-id\" does not exist: db.LookupById: record not found, search issue: error #1100", err.Error())
	})
}

func TestRepository_FailRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "code", "description")

	tests := []struct {
		name        string
		orig        *Run
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
			name: "status-already-final",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Interrupted.String(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).FailRun: db.DoTx: job.(Repository).FailRun: job run is already in a final run state: integrity violation: error #115",
		},
		{
			name: "valid",
			orig: &Run{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			var privateId string
			if tt.orig != nil {
				err = rw.Create(context.Background(), tt.orig)
				assert.NoError(err)
				assert.Empty(tt.orig.EndTime)
				privateId = tt.orig.PrivateId
			}

			got, err := repo.FailRun(context.Background(), privateId)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())

				if tt.orig != nil {
					// Delete job run so it does not clash with future runs
					_, err = repo.deleteRun(context.Background(), privateId)
					assert.NoError(err)
				}

				return
			}
			assert.NoError(err)
			require.NotNil(got)
			assert.NotEmpty(got.EndTime)
			assert.Equal(Failed.String(), got.Status)

			// Delete job run so it does not clash with future runs
			_, err = repo.deleteRun(context.Background(), privateId)
			assert.NoError(err)

			// Verify Run has oplog entry
			assert.NoError(db.TestVerifyOplog(t, rw, privateId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second), db.WithResourcePrivateId(true)))
		})
	}

	t.Run("job-run-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.FailRun(context.Background(), "fake-run-id")
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).FailRun: run \"fake-run-id\" does not exist: db.LookupById: record not found, search issue: error #1100", err.Error())
	})
}

func TestRepository_DuplicateJobRun(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)

	job1 := testJob(t, conn, "job1", "code1", "description")
	require.NotNil(job1)

	run, err := testRun(conn, job1.PrivateId, server.PrivateId)
	require.NoError(err)
	require.NotNil(run)

	// Inserting the same job run should conflict on jobId and status
	run, err = testRun(conn, job1.PrivateId, server.PrivateId)
	require.Error(err)
	require.Nil(run)
	assert.Equal("pq: duplicate key value violates unique constraint \"job_run_status_constraint\"", err.Error())

	// Creating a new job with a different name, the associated run should not conflict with the previous run
	job2 := testJob(t, conn, "job2", "code1", "description")
	require.NotNil(job1)

	run, err = testRun(conn, job2.PrivateId, server.PrivateId)
	require.NoError(err)
	require.NotNil(run)

	// Creating a new job with same name and different code should not conflict
	job1withCode := testJob(t, conn, "job1", "code2", "description")
	require.NotNil(job1)

	run.JobId = job1withCode.PrivateId

	run, err = testRun(conn, job1withCode.PrivateId, server.PrivateId)
	require.NoError(err)
	require.NotNil(run)
}

func TestRepository_LookupJobRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description")
	server := testController(t, conn, wrapper)
	run, err := testRun(conn, job.PrivateId, server.PrivateId)
	require.NoError(t, err)

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
			wantErrMsg:  "job.(Repository).LookupRun: missing private id: parameter violation: error #100",
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
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupRun(context.Background(), tt.in)
			if tt.wantErr {
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description")
	server := testController(t, conn, wrapper)

	run, err := testRun(conn, job.PrivateId, server.PrivateId)
	require.NoError(t, err)

	tests := []struct {
		name        string
		in          string
		want        int
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "With no private id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).deleteRun: missing private id: parameter violation: error #100",
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
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.deleteRun(context.Background(), tt.in)
			if tt.wantErr {
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
