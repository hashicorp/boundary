package job

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler/job/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	type args struct {
		name, code, description string
	}
	tests := []struct {
		name        string
		in          args
		want        *Job
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:    "missing-name",
			wantErr: true,
			in: args{
				code:        "code",
				description: "description",
			},
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: missing name: parameter violation: error #100",
		},
		{
			name: "missing-description",
			in: args{
				name: "name",
				code: "code",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: missing description: parameter violation: error #100",
		},
		{
			name: "missing-code",
			in: args{
				name:        "name",
				description: "description",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: missing code: parameter violation: error #100",
		},
		{
			name: "valid",
			in: args{
				name:        "name",
				code:        "code",
				description: "description",
			},
			want: &Job{
				Job: &store.Job{
					Name:        "name",
					Code:        "code",
					Description: "description",
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
			got, err := repo.CreateJob(context.Background(), tt.in.name, tt.in.code, tt.in.description)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.True(strings.HasPrefix(got.PrivateId, jobPrefix+"_"))
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(tt.want.Code, got.Code)
			assert.NotEmpty(got.NextScheduledRun)

			// Verify job has oplog entry
			assert.NoError(db.TestVerifyOplog(t, rw, got.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second), db.WithResourcePrivateId(true)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.CreateJob(context.Background(), "test-dup-name", "code", "description")
		require.NoError(err)
		require.NotNil(got)
		assert.True(strings.HasPrefix(got.PrivateId, jobPrefix+"_"))
		assert.Equal("test-dup-name", got.Name)
		assert.Equal("code", got.Code)
		assert.Equal("description", got.Description)

		got2, err := repo.CreateJob(context.Background(), "test-dup-name", "code", "description")
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		got2, err = repo.CreateJob(context.Background(), "test-dup-name-new", "code", "description")
		require.NoError(err)
		require.NotNil(got2)
		assert.NotSame(got, got2)
	})

	t.Run("duplicate-names-with-code", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.CreateJob(context.Background(), "test-dup-name-with-code", "code", "description")
		require.NoError(err)
		require.NotNil(got)
		assert.True(strings.HasPrefix(got.PrivateId, jobPrefix+"_"))
		assert.Equal("test-dup-name-with-code", got.Name)
		assert.Equal("code", got.Code)
		assert.Equal("description", got.Description)

		got2, err := repo.CreateJob(context.Background(), "test-dup-name-with-code", "code", "description")
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		got2, err = repo.CreateJob(context.Background(), "test-dup-name-with-code", "new-code", "description")
		require.NoError(err)
		require.NotNil(got2)
		assert.Equal(got.Name, got2.Name)
		assert.NotEqual(got.Code, got2.Code)
	})
}

func TestRepository_LookupJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description", wrapper)
	fakeJobId := "job_1234567890"

	tests := []struct {
		name        string
		in          string
		want        *Job
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "with-no-private-id",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).LookupJob: missing private id: parameter violation: error #100",
		},
		{
			name: "with-non-existing-job-id",
			in:   fakeJobId,
		},
		{
			name: "with-existing-job-id",
			in:   job.PrivateId,
			want: job,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupJob(context.Background(), tt.in)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Nil(got)
				return
			}
			require.NoError(err)
			if tt.want == nil {
				assert.Nil(got)
				return
			}

			assert.NotEmpty(got.NextScheduledRun)
			assert.NotEmpty(got.PrivateId)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(tt.want.Code, got.Code)
		})
	}
}

func TestRepository_deleteJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description", wrapper)
	fakeJobId := "job_1234567890"

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
			wantErrMsg:  "job.(Repository).deleteJob: missing private id: parameter violation: error #100",
		},
		{
			name: "With non existing job id",
			in:   fakeJobId,
			want: 0,
		},
		{
			name: "With existing job id",
			in:   job.PrivateId,
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
			got, err := repo.deleteJob(context.Background(), tt.in)
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

func TestRepository_ListJobs(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job1 := testJob(t, conn, "sameName", "sameCode", "description", wrapper)
	job2 := testJob(t, conn, "sameName", "differentCode", "description", wrapper)
	job3 := testJob(t, conn, "differentName", "sameCode", "description", wrapper)

	tests := []struct {
		name string
		opts []Option
		want []*Job
	}{
		{
			name: "no-options",
			want: []*Job{job1, job2, job3},
		},
		{
			name: "with-same-name",
			opts: []Option{
				WithName("sameName"),
			},
			want: []*Job{job1, job2},
		},
		{
			name: "with-different-name",
			opts: []Option{
				WithName("differentName"),
			},
			want: []*Job{job3},
		},
		{
			name: "with-same-code",
			opts: []Option{
				WithCode("sameCode"),
			},
			want: []*Job{job1, job3},
		},
		{
			name: "with-different-code",
			opts: []Option{
				WithCode("differentCode"),
			},
			want: []*Job{job2},
		},
		{
			name: "with-name-and-code",
			opts: []Option{
				WithName("sameName"),
				WithCode("sameCode"),
			},
			want: []*Job{job1},
		},
		{
			name: "with-fake-name",
			opts: []Option{
				WithName("fake-name"),
			},
			want: []*Job{},
		},
		{
			name: "with-fake-code",
			opts: []Option{
				WithName("fake-code"),
			},
			want: []*Job{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListJobs(context.Background(), tt.opts...)
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Job) bool { return x.PrivateId < y.PrivateId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.want, got, opts...))
		})
	}
}

func TestRepository_ListJobs_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	count := 10
	jobs := make([]*Job, count)
	for i := range jobs {
		jobs[i] = testJob(t, conn, "name", fmt.Sprintf("code-%d", i), "description", wrapper)
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
			got, err := repo.ListJobs(context.Background(), tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_UpdateJobNextRun(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		job, err := repo.CreateJob(context.Background(), "name", "code", "description")
		require.NoError(err)

		got, err := repo.UpdateJobNextRun(context.Background(), job.PrivateId, time.Hour)
		require.NoError(err)
		require.NotNil(got)

		previousRunAt := job.NextScheduledRun.Timestamp.GetSeconds()
		nextRunAt := got.NextScheduledRun.Timestamp.GetSeconds()
		assert.True(nextRunAt >= previousRunAt+int64(time.Hour.Seconds()),
			fmt.Sprintf("expected next run (%d) to be greater than or equal to the previous run (%d)",
				nextRunAt, previousRunAt))
		// update NextScheduledRun to pass equality check
		job.NextScheduledRun = got.NextScheduledRun
		assert.Equal(job, got)
	})

	t.Run("no-private-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.UpdateJobNextRun(context.Background(), "", time.Hour)
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).UpdateJobNextRun: missing private id: parameter violation: error #100", err.Error())
	})

	t.Run("job-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.UpdateJobNextRun(context.Background(), "fake-private-id", time.Hour)
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).UpdateJobNextRun: db.DoTx: job.(Repository).UpdateJobNextRun: job \"fake-private-id\" does not exist: search issue: error #1100", err.Error())
	})
}
