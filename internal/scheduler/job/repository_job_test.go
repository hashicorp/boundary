// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler/job/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_UpsertJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	type args struct {
		name, description string
	}
	tests := []struct {
		name        string
		in          *args
		want        *Job
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:    "missing-name",
			wantErr: true,
			in: &args{
				description: "description",
			},
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpsertJob: missing name: parameter violation: error #100",
		},
		{
			name: "missing-description",
			in: &args{
				name: "name",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpsertJob: missing description: parameter violation: error #100",
		},
		{
			name: "valid",
			in: &args{
				name:        "name",
				description: "description",
			},
			want: &Job{
				Job: &store.Job{
					Name:        "name",
					Description: "description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.UpsertJob(ctx, tt.in.name, tt.in.description)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(defaultPluginId, got.PluginId)
			assert.NotEmpty(got.NextScheduledRun)
		})
	}

	t.Run("re-register-same-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.UpsertJob(ctx, "test-dup-name", "description")
		require.NoError(err)
		require.NotNil(got)
		assert.Equal("test-dup-name", got.Name)
		assert.Equal("description", got.Description)

		got2, err := repo.UpsertJob(ctx, "test-dup-name", "updated description")
		require.NoError(err)
		require.NotNil(got2)
		assert.Equal("test-dup-name", got2.Name)
		assert.Equal("updated description", got2.Description)
	})
}

func TestRepository_LookupJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "description", wrapper)

	tests := []struct {
		name        string
		in          string
		want        *Job
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "with-no-name",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).LookupJob: missing name: parameter violation: error #100",
		},
		{
			name: "with-non-existing-name",
			in:   "fake-name",
		},
		{
			name: "with-existing-name",
			in:   job.Name,
			want: job,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupJob(ctx, tt.in)
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
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
		})
	}
}

func TestRepository_deleteJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "name", "description", wrapper)

	tests := []struct {
		name        string
		in          string
		want        int
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "With no name",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).deleteJob: missing name: parameter violation: error #100",
		},
		{
			name: "With non existing name",
			in:   "fake-name",
			want: 0,
		},
		{
			name: "With existing name",
			in:   job.Name,
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
			got, err := repo.deleteJob(ctx, tt.in)
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
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	job1 := testJob(t, conn, "sameName", "description", wrapper)
	job2 := testJob(t, conn, "differentName", "description", wrapper)

	tests := []struct {
		name string
		opts []Option
		want []*Job
	}{
		{
			name: "no-options",
			want: []*Job{job1, job2},
		},
		{
			name: "with-same-name",
			opts: []Option{
				WithName("sameName"),
			},
			want: []*Job{job1},
		},
		{
			name: "with-different-name",
			opts: []Option{
				WithName("differentName"),
			},
			want: []*Job{job2},
		},
		{
			name: "with-fake-name",
			opts: []Option{
				WithName("fake-name"),
			},
			want: []*Job{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListJobs(ctx, tt.opts...)
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Job) bool { return x.Name < y.Name }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.want, got, opts...))
		})
	}
}

func TestRepository_ListJobs_Limits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	count := 10
	jobs := make([]*Job, count)
	for i := range jobs {
		jobs[i] = testJob(t, conn, fmt.Sprintf("name-%d", i), "description", wrapper)
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
			repo, err := NewRepository(ctx, rw, rw, kms, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListJobs(ctx, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_UpdateJobNextRunInAtLeast(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		job, err := repo.UpsertJob(context.Background(), "valid", "description", WithNextRunIn(2*time.Hour))
		require.NoError(err)

		got, err := repo.UpdateJobNextRunInAtLeast(context.Background(), job.Name, time.Hour)
		require.NoError(err)
		require.NotNil(got)

		previousRunAt := job.NextScheduledRun.AsTime()
		nextRunAt := got.NextScheduledRun.AsTime()
		assert.Equal(nextRunAt.Round(time.Minute), previousRunAt.Add(-1*time.Hour).Round(time.Minute))
		// update NextScheduledRun to pass equality check
		job.NextScheduledRun = got.NextScheduledRun
		assert.Equal(job, got)
	})

	t.Run("next-run-already-sooner", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)
		job, err := repo.UpsertJob(context.Background(), "next-run-already-sooner", "description", WithNextRunIn(time.Hour))
		require.NoError(err)
		previousRunAt := job.NextScheduledRun.AsTime()

		got, err := repo.UpdateJobNextRunInAtLeast(context.Background(), job.Name, 2*time.Hour)
		require.NoError(err)
		require.NotNil(got)
		// Next run should not have been updated since its later than already scheduled
		assert.Equal(got.NextScheduledRun.AsTime(), previousRunAt)

		got, err = repo.UpdateJobNextRunInAtLeast(context.Background(), job.Name, time.Minute)
		require.NoError(err)
		require.NotNil(got)
		// Next run should be less than previous run at
		assert.True(got.NextScheduledRun.AsTime().Before(previousRunAt))
		previousRunAt = got.NextScheduledRun.AsTime()

		got, err = repo.UpdateJobNextRunInAtLeast(context.Background(), job.Name, time.Hour)
		require.NoError(err)
		require.NotNil(got)
		// Next run should not have been updated since its later than already scheduled
		assert.Equal(got.NextScheduledRun.AsTime(), previousRunAt)
	})

	t.Run("no-name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.UpdateJobNextRunInAtLeast(context.Background(), "", time.Hour)
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).UpdateJobNextRunInAtLeast: missing name: parameter violation: error #100", err.Error())
	})

	t.Run("job-not-found", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(err)
		require.NotNil(repo)

		got, err := repo.UpdateJobNextRunInAtLeast(context.Background(), "fake-name", time.Hour)
		require.Error(err)
		require.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "Unexpected error %s", err)
		assert.Equal("job.(Repository).UpdateJobNextRunInAtLeast: db.DoTx: job.(Repository).UpdateJobNextRunInAtLeast: job \"fake-name\" does not exist: search issue: error #1100", err.Error())
	})
}
