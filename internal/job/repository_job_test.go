package job

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/job/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRepository_CreateJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	ts := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(time.Hour))}
	tests := []struct {
		name        string
		in          *Job
		want        *Job
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "nil-job",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: missing job: parameter violation: error #100",
		},
		{
			name:        "nil-embedded-job",
			in:          &Job{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: missing embedded job: parameter violation: error #100",
		},
		{
			name: "missing-name",
			in: &Job{
				Job: &store.Job{},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: missing name: parameter violation: error #100",
		},
		{
			name: "missing-description",
			in: &Job{
				Job: &store.Job{
					Name: "name",
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: missing description: parameter violation: error #100",
		},
		{
			name: "missing-next-run",
			in: &Job{
				Job: &store.Job{
					Name:        "name",
					Description: "description",
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: missing next scheduled run: parameter violation: error #100",
		},
		{
			name: "included-private-id",
			in: &Job{
				Job: &store.Job{
					PrivateId:        "job_1234",
					Name:             "name",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).CreateJob: private id not empty: parameter violation: error #100",
		},
		{
			name: "valid",
			in: &Job{
				Job: &store.Job{
					Name:             "name",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			want: &Job{
				Job: &store.Job{
					Name:             "name",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
		},
		{
			name: "valid-with-new-code",
			in: &Job{
				Job: &store.Job{
					Name:             "name",
					Description:      "description",
					Code:             "new-code",
					NextScheduledRun: ts,
				},
			},
			want: &Job{
				Job: &store.Job{
					Name:             "name",
					Description:      "description",
					Code:             "new-code",
					NextScheduledRun: ts,
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
			got, err := repo.CreateJob(context.Background(), tt.in)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.True(strings.HasPrefix(got.PrivateId, JobPrefix+"_"))
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(tt.want.Code, got.Code)
			assert.Equal(tt.want.NextScheduledRun.Timestamp, got.NextScheduledRun.Timestamp)
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		in := &Job{
			Job: &store.Job{
				Name:             "test-dup-name",
				Code:             "code",
				Description:      "description",
				NextScheduledRun: ts,
			},
		}

		got, err := repo.CreateJob(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assert.True(strings.HasPrefix(got.PrivateId, JobPrefix+"_"))
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		got2, err := repo.CreateJob(context.Background(), in)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		in.Name = "test-dup-name-new"
		got2, err = repo.CreateJob(context.Background(), in)
		require.NoError(err)
		require.NotNil(got2)
		assert.NotSame(got, got2)
	})

	t.Run("duplicate-names-with-code", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		in := &Job{
			Job: &store.Job{
				Name:             "test-dup-name-with-code",
				Code:             "code",
				Description:      "description",
				NextScheduledRun: ts,
			},
		}

		got, err := repo.CreateJob(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assert.True(strings.HasPrefix(got.PrivateId, JobPrefix+"_"))
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		got2, err := repo.CreateJob(context.Background(), in)
		require.Error(err)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		in.Code = "new code"
		got2, err = repo.CreateJob(context.Background(), in)
		require.NoError(err)
		require.NotNil(got2)
		assert.Equal(got.Name, got2.Name)
		assert.NotEqual(got.Code, got2.Code)
	})
}

func TestRepository_UpdateJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	ts := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(time.Hour))}
	newTs := &timestamp.Timestamp{Timestamp: timestamppb.New(time.Now().Add(2 * time.Hour))}
	changeDescription := func(s string) func(*Job) *Job {
		return func(j *Job) *Job {
			j.Description = s
			return j
		}
	}

	changeNextScheduledRun := func(t *timestamp.Timestamp) func(*Job) *Job {
		return func(j *Job) *Job {
			j.NextScheduledRun = t
			return j
		}
	}

	makeNil := func() func(*Job) *Job {
		return func(_ *Job) *Job {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*Job) *Job {
		return func(_ *Job) *Job {
			return &Job{}
		}
	}

	deletePrivateId := func() func(*Job) *Job {
		return func(j *Job) *Job {
			j.PrivateId = ""
			return j
		}
	}

	nonExistentPrivateId := func() func(*Job) *Job {
		return func(j *Job) *Job {
			j.PrivateId = "abcd_OOOOOOOOOO"
			return j
		}
	}

	combine := func(fns ...func(j *Job) *Job) func(*Job) *Job {
		return func(j *Job) *Job {
			for _, fn := range fns {
				j = fn(j)
			}
			return j
		}
	}

	tests := []struct {
		name        string
		orig        *Job
		chgFn       func(*Job) *Job
		masks       []string
		want        *Job
		wantCount   int
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name: "nil-job",
			orig: &Job{
				Job: &store.Job{
					Name:             "nil-job-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn:       makeNil(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpdateJob: missing job: parameter violation: error #100",
		},
		{
			name: "nil-embedded-job",
			orig: &Job{
				Job: &store.Job{
					Name:             "nil-embedded-job-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn:       makeEmbeddedNil(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpdateJob: missing embedded job: parameter violation: error #100",
		},
		{
			name: "no-private-id",
			orig: &Job{
				Job: &store.Job{
					Name:             "no-private-id-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn:       deletePrivateId(),
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.(Repository).UpdateJob: missing private id: parameter violation: error #100",
		},
		{
			name: "updating-non-existent-job",
			orig: &Job{
				Job: &store.Job{
					Name:             "updating-non-existent-job-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn:       combine(nonExistentPrivateId(), changeDescription("test-update-description")),
			masks:       []string{"Description"},
			wantErr:     true,
			wantErrCode: errors.RecordNotFound,
			wantErrMsg:  "job.(Repository).UpdateJob: db.DoTx: job.(Repository).UpdateJob: db.Update: db.lookupAfterWrite: db.LookupById: record not found, search issue: error #1100",
		},
		{
			name: "empty-field-mask",
			orig: &Job{
				Job: &store.Job{
					Name:             "empty-field-mask-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn:       changeDescription("test-update-description"),
			wantErr:     true,
			wantErrCode: errors.EmptyFieldMask,
			wantErrMsg:  "job.(Repository).UpdateJob: empty field mask: parameter violation: error #104",
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &Job{
				Job: &store.Job{
					Name:             "read-only-fields-in-field-mask-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn:       changeDescription("test-update-description"),
			masks:       []string{"PrivateId", "Name", "Code"},
			wantErr:     true,
			wantErrCode: errors.InvalidFieldMask,
			wantErrMsg:  "job.(Repository).UpdateJob: invalid field mask: PrivateId: parameter violation: error #103",
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &Job{
				Job: &store.Job{
					Name:             "unknown-field-in-field-mask-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn:       changeDescription("test-update-description"),
			masks:       []string{"Bilbo"},
			wantErr:     true,
			wantErrCode: errors.InvalidFieldMask,
			wantErrMsg:  "job.(Repository).UpdateJob: invalid field mask: Bilbo: parameter violation: error #103",
		},
		{
			name: "change-description",
			orig: &Job{
				Job: &store.Job{
					Name:             "change-description-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn: changeDescription("test-update-description"),
			masks: []string{"Description"},
			want: &Job{
				Job: &store.Job{
					Name:             "change-description-test",
					Code:             "code",
					Description:      "test-update-description",
					NextScheduledRun: ts,
				},
			},
			wantCount: 1,
		},
		{
			name: "change-next-run",
			orig: &Job{
				Job: &store.Job{
					Name:             "change-next-run-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn: changeNextScheduledRun(newTs),
			masks: []string{"NextScheduledRun"},
			want: &Job{
				Job: &store.Job{
					Name:             "change-next-run-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: newTs,
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description-and-next-run",
			orig: &Job{
				Job: &store.Job{
					Name:             "change-description-and-next-run-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: ts,
				},
			},
			chgFn: combine(changeDescription("test-update-description"), changeNextScheduledRun(newTs)),
			masks: []string{"Description", "NextScheduledRun"},
			want: &Job{
				Job: &store.Job{
					Name:             "change-description-and-next-run-test",
					Code:             "code",
					Description:      "test-update-description",
					NextScheduledRun: newTs,
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

			orig, err := repo.CreateJob(context.Background(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}

			got, gotCount, err := repo.UpdateJob(context.Background(), orig, tt.masks)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}

			assert.NoError(err)
			assert.Empty(tt.orig.PrivateId)
			require.NotNil(got)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)

			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(tt.want.NextScheduledRun.Timestamp, got.NextScheduledRun.Timestamp)
		})
	}
}

func TestRepository_LookupJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description")
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

func TestRepository_deleteJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	job := testJob(t, conn, "name", "code", "description")
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
			wantErrMsg:  "job.(Repository).DeleteJob: missing private id: parameter violation: error #100",
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
