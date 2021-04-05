package job

import (
	"context"
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

func TestRepository_FetchWork(t *testing.T) {
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
			wantErrMsg:  "job.(Repository).FetchWork: missing server id: parameter violation: error #100",
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
			wantErrMsg:  "job.(Repository).FetchWork: db.DoTx: job.(Repository).FetchWork: db.Create: create failed: insert or update on table \"job_run\" violates foreign key constraint \"server_fkey\": integrity violation: error #1003",
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

			got, err := repo.FetchWork(context.Background(), tt.serverId)
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

			assert.NotNil(got)
			assert.Equal(jId, got.JobId)
		})
	}
}

func TestRepository_FetchWorkOrder(t *testing.T) {
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
	lastJob := testJob(t, conn, "future", "code", "description", WithNextScheduledRun(time.Now().Add(-1*time.Hour)))
	firstJob := testJob(t, conn, "past", "code", "description", WithNextScheduledRun(time.Now().Add(-24*time.Hour)))
	middleJob := testJob(t, conn, "current", "code", "description", WithNextScheduledRun(time.Now().Add(-12*time.Hour)))

	got, err := repo.FetchWork(context.Background(), server.PrivateId)
	require.NoError(err)
	require.NotNil(got)
	assert.Equal(got.JobId, firstJob.PrivateId)

	// End first job with time between last and middle
	err = repo.EndJobRun(context.Background(), got.PrivateId, Completed, time.Now().Add(-6*time.Hour))
	require.NoError(err)

	got, err = repo.FetchWork(context.Background(), server.PrivateId)
	require.NoError(err)
	require.NotNil(got)
	assert.Equal(got.JobId, middleJob.PrivateId)

	// firstJob should be up again, as it is scheduled before lastJob
	got, err = repo.FetchWork(context.Background(), server.PrivateId)
	require.NoError(err)
	require.NotNil(got)
	assert.Equal(got.JobId, firstJob.PrivateId)

	got, err = repo.FetchWork(context.Background(), server.PrivateId)
	require.NoError(err)
	require.NotNil(got)
	assert.Equal(got.JobId, lastJob.PrivateId)

	// All jobs are running no work should be returned
	got, err = repo.FetchWork(context.Background(), server.PrivateId)
	require.NoError(err)
	require.Nil(got)
}

func TestRepository_CheckpointJobRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "code", "description")

	changeCompleted := func(i uint32) func(*JobRun) *JobRun {
		return func(r *JobRun) *JobRun {
			r.CompletedCount = i
			return r
		}
	}

	changeTotal := func(i uint32) func(*JobRun) *JobRun {
		return func(r *JobRun) *JobRun {
			r.TotalCount = i
			return r
		}
	}

	makeNil := func() func(*JobRun) *JobRun {
		return func(_ *JobRun) *JobRun {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*JobRun) *JobRun {
		return func(_ *JobRun) *JobRun {
			return &JobRun{}
		}
	}

	deleteId := func() func(*JobRun) *JobRun {
		return func(r *JobRun) *JobRun {
			r.PrivateId = ""
			return r
		}
	}

	nonExistentId := func() func(*JobRun) *JobRun {
		return func(r *JobRun) *JobRun {
			r.PrivateId = JobRunPrefix + "_1234567890"
			return r
		}
	}

	combine := func(fns ...func(j *JobRun) *JobRun) func(*JobRun) *JobRun {
		return func(r *JobRun) *JobRun {
			for _, fn := range fns {
				r = fn(r)
			}
			return r
		}
	}

	tests := []struct {
		name        string
		orig        *JobRun
		chgFn       func(*JobRun) *JobRun
		masks       []string
		want        *JobRun
		wantCount   int
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name: "nil-job-run",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			chgFn:       makeNil(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: missing job run: parameter violation: error #100",
		},
		{
			name: "nil-embedded-job",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			chgFn:       makeEmbeddedNil(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: missing embedded job run: parameter violation: error #100",
		},
		{
			name: "no-id",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			chgFn:       deleteId(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: missing private id: parameter violation: error #100",
		},
		{
			name: "updating-non-existent-job",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			chgFn:       combine(nonExistentId(), changeTotal(10)),
			masks:       []string{"TotalCount"},
			wantErr:     true,
			wantErrCode: errors.RecordNotFound,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: db.DoTx: job.(Repository).CheckpointJobRun: db.Update: db.lookupAfterWrite: db.LookupById: record not found, search issue: error #1100",
		},
		{
			name: "empty-field-mask",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			chgFn:       changeTotal(10),
			wantErr:     true,
			wantErrCode: errors.EmptyFieldMask,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: empty field mask: parameter violation: error #104",
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			chgFn:       changeTotal(10),
			masks:       []string{"PrivateId", "Status", "EndTime", "JobId", "ServerId", "CreateTime", "UpdateTime"},
			wantErr:     true,
			wantErrCode: errors.InvalidFieldMask,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: invalid field mask: PrivateId: parameter violation: error #103",
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			chgFn:       changeTotal(10),
			masks:       []string{"Bilbo"},
			wantErr:     true,
			wantErrCode: errors.InvalidFieldMask,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: invalid field mask: Bilbo: parameter violation: error #103",
		},
		{
			name: "change-completed-count",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:          job.PrivateId,
					ServerId:       server.PrivateId,
					Status:         Running.String(),
					CompletedCount: 0,
					TotalCount:     100,
				},
			},
			chgFn: changeCompleted(50),
			masks: []string{"CompletedCount"},
			want: &JobRun{
				JobRun: &store.JobRun{
					JobId:          job.PrivateId,
					ServerId:       server.PrivateId,
					Status:         Running.String(),
					CompletedCount: 50,
					TotalCount:     100,
				},
			},
			wantCount: 1,
		},
		{
			name: "change-total-count",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:          job.PrivateId,
					ServerId:       server.PrivateId,
					Status:         Running.String(),
					CompletedCount: 0,
					TotalCount:     100,
				},
			},
			chgFn: changeTotal(200),
			masks: []string{"TotalCount"},
			want: &JobRun{
				JobRun: &store.JobRun{
					JobId:          job.PrivateId,
					ServerId:       server.PrivateId,
					Status:         Running.String(),
					CompletedCount: 0,
					TotalCount:     200,
				},
			},
			wantCount: 1,
		},
		{
			name: "change-completed-and-total-count",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:          job.PrivateId,
					ServerId:       server.PrivateId,
					Status:         Running.String(),
					CompletedCount: 0,
					TotalCount:     100,
				},
			},
			chgFn: combine(changeCompleted(50), changeTotal(200)),
			masks: []string{"CompletedCount", "TotalCount"},
			want: &JobRun{
				JobRun: &store.JobRun{
					JobId:          job.PrivateId,
					ServerId:       server.PrivateId,
					Status:         Running.String(),
					CompletedCount: 50,
					TotalCount:     200,
				},
			},
			wantCount: 1,
		},
		{
			name: "invalid-change-run-completed",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Completed.String(),
				},
			},
			masks:       []string{"TotalCount"},
			chgFn:       changeTotal(10),
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: db.DoTx: job.(Repository).CheckpointJobRun: job run is already in a final run state: integrity violation: error #115",
		},
		{
			name: "invalid-change-run-failed",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Failed.String(),
				},
			},
			masks:       []string{"TotalCount"},
			chgFn:       changeTotal(10),
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: db.DoTx: job.(Repository).CheckpointJobRun: job run is already in a final run state: integrity violation: error #115",
		},
		{
			name: "invalid-change-run-interrupted",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Interrupted.String(),
				},
			},
			masks:       []string{"TotalCount"},
			chgFn:       changeTotal(10),
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).CheckpointJobRun: db.DoTx: job.(Repository).CheckpointJobRun: job run is already in a final run state: integrity violation: error #115",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			orig := tt.orig.clone()
			id, err := newJobRunId()
			assert.NoError(err)
			orig.PrivateId = id
			err = rw.Create(context.Background(), orig)
			assert.NoError(err)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}

			got, gotCount, err := repo.CheckpointJobRun(context.Background(), orig, tt.masks)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)

				// Delete job run so it does not clash with future runs
				_, err = repo.deleteJobRun(context.Background(), id)
				assert.NoError(err)
				return
			}

			assert.NoError(err)
			assert.Empty(tt.orig.PrivateId)
			require.NotNil(got)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)

			assert.NotEmpty(got.UpdateTime)
			assert.Equal(tt.want.Status, got.Status)
			assert.Equal(tt.want.CompletedCount, got.CompletedCount)
			assert.Equal(tt.want.TotalCount, got.TotalCount)

			// Delete job run so it does not clash with future runs
			_, err = repo.deleteJobRun(context.Background(), id)
			assert.NoError(err)
		})
	}
}

func TestRepository_EndJobRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "code", "description")

	type args struct {
		status           Status
		nextScheduledRun time.Time
	}

	futureTime := time.Now().Add(time.Hour)

	tests := []struct {
		name        string
		orig        *JobRun
		args        args
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "no-private-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).EndJobRun: missing private id: parameter violation: error #100",
		},
		{
			name: "no-status",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).EndJobRun: run status must be a final status (completed, failed or interrupted): parameter violation: error #100",
		},
		{
			name: "invalid-status",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			args: args{
				status: "fake-status",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).EndJobRun: run status must be a final status (completed, failed or interrupted): parameter violation: error #100",
		},
		{
			name: "running-status",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			args: args{
				status: Running,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).EndJobRun: run status must be a final status (completed, failed or interrupted): parameter violation: error #100",
		},
		{
			name: "invalid-next-run",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			args: args{
				status: Completed,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).EndJobRun: missing next scheduled run: parameter violation: error #100",
		},
		{
			name: "run-status-already-final",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Interrupted.String(),
				},
			},
			args: args{
				status:           Completed,
				nextScheduledRun: futureTime,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidJobRunState,
			wantErrMsg:  "job.(Repository).EndJobRun: db.DoTx: job.(Repository).EndJobRun: job run is already in a final run state: integrity violation: error #115",
		},
		{
			name: "valid",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   Running.String(),
				},
			},
			args: args{
				status:           Completed,
				nextScheduledRun: futureTime,
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
				privateId, err = newJobRunId()
				assert.NoError(err)
				tt.orig.PrivateId = privateId
				err = rw.Create(context.Background(), tt.orig)
				assert.NoError(err)
				assert.Empty(tt.orig.EndTime)
			}

			err = repo.EndJobRun(context.Background(), privateId, tt.args.status, tt.args.nextScheduledRun)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())

				if privateId != "" {
					// Delete job run so it does not clash with future runs
					_, err = repo.deleteJobRun(context.Background(), privateId)
					assert.NoError(err)
				}

				return
			}
			assert.NoError(err)

			updatedRun, err := repo.LookupJobRun(context.Background(), privateId)
			assert.NoError(err)
			require.NotNil(updatedRun)
			assert.NotEmpty(updatedRun.EndTime)
			assert.Equal(tt.args.status.String(), updatedRun.Status)

			updatedJob, err := repo.LookupJob(context.Background(), tt.orig.JobId)
			assert.NoError(err)
			require.NotNil(updatedJob)
			assert.Equal(tt.args.nextScheduledRun.Unix(), updatedJob.NextScheduledRun.Timestamp.GetSeconds())

			// Delete job run so it does not clash with future runs
			_, err = repo.deleteJobRun(context.Background(), privateId)
			assert.NoError(err)

			// Verify JobRun has oplog entry
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

		err = repo.EndJobRun(context.Background(), "fake-run-id", Completed, futureTime)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).EndJobRun: job run \"fake-run-id\" not found: db.LookupById: record not found, search issue: error #1100", err.Error())
	})
}

func TestRepository_DuplicateJobRun(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)

	job1 := testJob(t, conn, "job1", "code1", "description")
	require.NotNil(job1)

	run := &JobRun{
		JobRun: &store.JobRun{
			JobId:    job1.PrivateId,
			ServerId: server.PrivateId,
			Status:   Running.String(),
		},
	}

	id, err := newJobRunId()
	require.NoError(err)
	run.PrivateId = id
	err = rw.Create(context.Background(), run)
	assert.NoError(err)

	// Inserting the same job run with a different private id should still conflict on jobId and status
	id, err = newJobRunId()
	require.NoError(err)
	run.PrivateId = id
	err = rw.Create(context.Background(), run)
	assert.Error(err)
	assert.Equal("db.Create: create failed: duplicate key value violates unique constraint \"job_run_status_constraint\": unique constraint violation: integrity violation: error #1002", err.Error())

	// Creating a new job with a different name, the associated run should not conflict with the previous run
	job2 := testJob(t, conn, "job2", "code1", "description")
	require.NotNil(job1)

	run.JobId = job2.PrivateId

	id, err = newJobRunId()
	require.NoError(err)
	run.PrivateId = id
	err = rw.Create(context.Background(), run)
	assert.NoError(err)

	// Creating a new job with same name and different code should not conflict
	job1withCode := testJob(t, conn, "job1", "code2", "description")
	require.NotNil(job1)

	run.JobId = job1withCode.PrivateId

	id, err = newJobRunId()
	require.NoError(err)
	run.PrivateId = id
	err = rw.Create(context.Background(), run)
	assert.NoError(err)
}

func TestRepository_LookupJobRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description")
	server := testController(t, conn, wrapper)
	run := testJobRun(t, conn, job.PrivateId, server.PrivateId, Running)
	fakeId := JobRunPrefix + "_1234567890"

	tests := []struct {
		name        string
		in          string
		want        *JobRun
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "with-no-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).LookupJobRun: missing private id: parameter violation: error #100",
		},
		{
			name: "with-non-existing-id",
			in:   fakeId,
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
			got, err := repo.LookupJobRun(context.Background(), tt.in)
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

	run := testJobRun(t, conn, job.PrivateId, server.PrivateId, "running")
	fakeRunId := JobRunPrefix + "_1234567890"

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
			wantErrMsg:  "job.(Repository).deleteJobRun: missing private id: parameter violation: error #100",
		},
		{
			name: "With non existing job id",
			in:   fakeRunId,
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
			got, err := repo.deleteJobRun(context.Background(), tt.in)
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
