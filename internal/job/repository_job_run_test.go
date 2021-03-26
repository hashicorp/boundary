package job

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/job/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRepository_CreateJobRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "code", "description")

	tests := []struct {
		name        string
		in          *JobRun
		want        *JobRun
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "nil-job-run",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJobRun: missing job run: parameter violation: error #100",
		},
		{
			name:        "nil-embedded-job-run",
			in:          &JobRun{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJobRun: missing embedded job run: parameter violation: error #100",
		},
		{
			name: "missing-job-id",
			in: &JobRun{
				JobRun: &store.JobRun{},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJobRun: missing job id: parameter violation: error #100",
		},
		{
			name: "missing-server-id",
			in: &JobRun{
				JobRun: &store.JobRun{
					JobId: job.PrivateId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJobRun: missing server id: parameter violation: error #100",
		},
		{
			name: "invalid-id",
			in: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Id:       1,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJobRun: id must not be set: parameter violation: error #100",
		},
		{
			name: "invalid-job-id",
			in: &JobRun{
				JobRun: &store.JobRun{
					JobId:    "test-job-id",
					ServerId: server.PrivateId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.NotSpecificIntegrity,
			wantErrMsg:  "job.(Repository).CreateJobRun: db.DoTx: job.(Repository).CreateJobRun: db.Create: create failed: insert or update on table \"job_run\" violates foreign key constraint \"job_fkey\": integrity violation: error #1003",
		},
		{
			name: "invalid-server-id",
			in: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: "test-server-id",
				},
			},
			wantErr:     true,
			wantErrCode: errors.NotSpecificIntegrity,
			wantErrMsg:  "job.(Repository).CreateJobRun: db.DoTx: job.(Repository).CreateJobRun: db.Create: create failed: insert or update on table \"job_run\" violates foreign key constraint \"server_fkey\": integrity violation: error #1003",
		},
		{
			name: "invalid-status",
			in: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   "bad",
				},
			},
			wantErr:     true,
			wantErrCode: errors.NotSpecificIntegrity,
			wantErrMsg:  "job.(Repository).CreateJobRun: db.DoTx: job.(Repository).CreateJobRun: db.Create: create failed: insert or update on table \"job_run\" violates foreign key constraint \"job_run_status_enm_fkey\": integrity violation: error #1003",
		},
		{
			name: "valid",
			in: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Running),
				},
			},
			want: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Running),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateJobRun(context.Background(), tt.in)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.JobId, got.JobId)
			assert.Equal(tt.want.ServerId, got.ServerId)
			assert.Equal(tt.want.Status, got.Status)
			assert.NotEmpty(got.CreateTime)
		})
	}
}

func TestRepository_UpdateJobRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	server := testController(t, conn, wrapper)
	job := testJob(t, conn, "name", "code", "description")
	ts := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(time.Hour))}
	newTs := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(2 * time.Hour))}

	changeStatus := func(s RunStatus) func(*JobRun) *JobRun {
		return func(r *JobRun) *JobRun {
			r.Status = string(s)
			return r
		}
	}

	changeEndtime := func(t *timestamp.Timestamp) func(*JobRun) *JobRun {
		return func(r *JobRun) *JobRun {
			r.EndTime = t
			return r
		}
	}

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
			r.Id = 0
			return r
		}
	}

	nonExistentId := func() func(*JobRun) *JobRun {
		return func(r *JobRun) *JobRun {
			r.Id = 1000
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
					Status:   string(Completed),
				},
			},
			chgFn:       makeNil(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpdateJobRun: missing job run: parameter violation: error #100",
		},
		{
			name: "nil-embedded-job",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
				},
			},
			chgFn:       makeEmbeddedNil(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpdateJobRun: missing embedded job run: parameter violation: error #100",
		},
		{
			name: "no-id",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
				},
			},
			chgFn:       deleteId(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpdateJobRun: missing id: parameter violation: error #100",
		},
		{
			name: "updating-non-existent-job",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
				},
			},
			chgFn:       combine(nonExistentId(), changeStatus(Failed)),
			masks:       []string{"Status"},
			wantErr:     true,
			wantErrCode: errors.RecordNotFound,
			wantErrMsg:  "job.(Repository).UpdateJobRun: db.DoTx: job.(Repository).UpdateJobRun: db.Update: db.lookupAfterWrite: db.LookupById: record not found, search issue: error #1100",
		},
		{
			name: "empty-field-mask",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
				},
			},
			chgFn:       changeStatus(Failed),
			wantErr:     true,
			wantErrCode: errors.EmptyFieldMask,
			wantErrMsg:  "job.(Repository).UpdateJobRun: empty field mask: parameter violation: error #104",
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
				},
			},
			chgFn:       changeStatus(Failed),
			masks:       []string{"Id", "JobId", "ServerId", "CreateTime", "UpdateTime"},
			wantErr:     true,
			wantErrCode: errors.InvalidFieldMask,
			wantErrMsg:  "job.(Repository).UpdateJobRun: invalid field mask: Id: parameter violation: error #103",
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
				},
			},
			chgFn:       changeStatus(Failed),
			masks:       []string{"Bilbo"},
			wantErr:     true,
			wantErrCode: errors.InvalidFieldMask,
			wantErrMsg:  "job.(Repository).UpdateJobRun: invalid field mask: Bilbo: parameter violation: error #103",
		},
		{
			name: "change-status",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
				},
			},
			chgFn: changeStatus(Failed),
			masks: []string{"Status"},
			want: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Failed),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-end-time",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
					EndTime:  ts,
				},
			},
			chgFn: changeEndtime(newTs),
			masks: []string{"EndTime"},
			want: &JobRun{
				JobRun: &store.JobRun{
					JobId:    job.PrivateId,
					ServerId: server.PrivateId,
					Status:   string(Completed),
					EndTime:  newTs,
				},
			},
			wantCount: 1,
		},
		{
			name: "change-completed-count",
			orig: &JobRun{
				JobRun: &store.JobRun{
					JobId:          job.PrivateId,
					ServerId:       server.PrivateId,
					Status:         string(Completed),
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
					Status:         string(Completed),
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
					Status:         string(Completed),
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
					Status:         string(Completed),
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
					Status:         string(Completed),
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
					Status:         string(Completed),
					CompletedCount: 50,
					TotalCount:     200,
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			orig, err := repo.CreateJobRun(context.Background(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}

			got, gotCount, err := repo.UpdateJobRun(context.Background(), orig, tt.masks)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}

			assert.NoError(err)
			assert.Empty(tt.orig.Id)
			require.NotNil(got)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)

			assert.NotEmpty(got.UpdateTime)
			assert.Equal(tt.want.Status, got.Status)
			assert.Equal(tt.want.CompletedCount, got.CompletedCount)
			assert.Equal(tt.want.TotalCount, got.TotalCount)
			assert.Equal(tt.want.EndTime, got.EndTime)
		})
	}

	t.Run("duplicate-job-run", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		run, err := NewJobRun(job.PrivateId, server.PrivateId)
		require.NoError(err)
		require.NotNil(run)

		dbRun, err := repo.CreateJobRun(context.Background(), run)
		require.NoError(err)
		require.NotNil(dbRun)
		assert.NotEmpty(dbRun.Id)

		// Attempting to create the same job run must fail since previous run is still active
		assert.Empty(run.Id)
		newDbRun, err := repo.CreateJobRun(context.Background(), run)
		require.Error(err)
		require.Nil(newDbRun)
		assert.Contains(err.Error(), fmt.Sprintf("job.(Repository).CreateJobRun: job %v already running", job.PrivateId))

		// Update previous run to be complete
		dbRun.Status = string(Completed)
		dbRun, count, err := repo.UpdateJobRun(context.Background(), dbRun, []string{"Status"})
		require.NoError(err)
		assert.Equal(1, count)

		// Attempting to create the same job run should succeed since previous run is complete
		assert.Empty(run.Id)
		newDbRun, err = repo.CreateJobRun(context.Background(), run)
		require.NoError(err)
		require.NotNil(newDbRun)
	})
}

func TestRepository_LookupJobRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description")
	server := testController(t, conn, wrapper)
	run := testJobRun(t, conn, job.PrivateId, server.PrivateId)
	var fakeId int64 = 100

	tests := []struct {
		name        string
		in          int64
		want        *JobRun
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "with-no-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).LookupJobRun: missing id: parameter violation: error #100",
		},
		{
			name: "with-non-existing-id",
			in:   fakeId,
		},
		{
			name: "with-existing-id",
			in:   run.Id,
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

func TestRepository_ListJobRuns(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	job1 := testJob(t, conn, "job1", "code", "description")
	job2 := testJob(t, conn, "job2", "code", "description")
	server := testController(t, conn, wrapper)

	run1 := testJobRun(t, conn, job1.PrivateId, server.PrivateId, WithJobRunStatus(Completed))
	run2 := testJobRun(t, conn, job1.PrivateId, server.PrivateId, WithJobRunStatus(Completed))
	run3 := testJobRun(t, conn, job2.PrivateId, server.PrivateId, WithJobRunStatus(Completed))

	tests := []struct {
		name        string
		in          string
		opts        []Option
		want        []*JobRun
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "with-no-job_id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).ListJobRuns: missing job id: parameter violation: error #100",
		},
		{
			name: "with-job1-id",
			in:   job1.PrivateId,
			want: []*JobRun{run1, run2},
		},
		{
			name: "with-job2-id",
			in:   job2.PrivateId,
			want: []*JobRun{run3},
		},
		{
			name: "with-fake-job-id",
			in:   "job_1234567890",
			want: []*JobRun{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListJobRuns(context.Background(), tt.in, tt.opts...)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Job) bool { return x.PrivateId < y.PrivateId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.want, got, opts...))
		})
	}
}

func TestRepository_ListJobRuns_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	job := testJob(t, conn, "job", "code", "description")
	server := testController(t, conn, wrapper)

	count := 10
	runs := make([]*JobRun, count)
	for i := range runs {
		runs[i] = testJobRun(t, conn, job.PrivateId, server.PrivateId, WithJobRunStatus(Completed))
	}

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: count,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []Option{WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []Option{WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListJobRuns(context.Background(), job.PrivateId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_DeleteJobRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description")
	server := testController(t, conn, wrapper)

	run := testJobRun(t, conn, job.PrivateId, server.PrivateId)
	var fakeRunId int64 = 100

	tests := []struct {
		name        string
		in          int64
		want        int
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "With no private id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).DeleteJobRun: missing id: parameter violation: error #100",
		},
		{
			name: "With non existing job id",
			in:   fakeRunId,
			want: 0,
		},
		{
			name: "With existing job id",
			in:   run.Id,
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
			got, err := repo.DeleteJobRun(context.Background(), tt.in)
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
