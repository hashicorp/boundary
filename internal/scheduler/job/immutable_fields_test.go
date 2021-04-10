package job

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestJob_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	oriJob := testJob(t, conn, "name", "code", "description", wrapper)

	tests := []struct {
		name      string
		update    *Job
		fieldMask []string
	}{
		{
			name: "private id",
			update: func() *Job {
				j := oriJob.clone()
				j.PrivateId = "job_test-private-id"
				return j
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "name",
			update: func() *Job {
				j := oriJob.clone()
				j.Name = "new name"
				return j
			}(),
			fieldMask: []string{"Name"},
		},
		{
			name: "code",
			update: func() *Job {
				j := oriJob.clone()
				j.Code = "new code"
				return j
			}(),
			fieldMask: []string{"Code"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := oriJob.clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := oriJob.clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}

func TestJobRun_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)
	w := db.New(conn)
	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	job := testJob(t, conn, "testJob", "testCode", "testDescription", wrapper)
	server := testController(t, conn, wrapper)
	oriRun, err := testRun(conn, job.PrivateId, server.PrivateId)
	require.NoError(t, err)

	tests := []struct {
		name      string
		update    *Run
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *Run {
				j := oriRun.clone()
				j.PrivateId = "new-run-id"
				return j
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "job id",
			update: func() *Run {
				j := oriRun.clone()
				j.JobId = "job_test-private-id"
				return j
			}(),
			fieldMask: []string{"JobId"},
		},
		{
			name: "create time",
			update: func() *Run {
				j := oriRun.clone()
				j.CreateTime = &ts
				return j
			}(),
			fieldMask: []string{"CreateTime"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := oriRun.clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := oriRun.clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}
