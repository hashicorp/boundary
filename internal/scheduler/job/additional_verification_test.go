package job

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestJobWorkflow(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)

	repo, err := NewRepository(rw, rw, kms)
	assert.NoError(err)

	job, err := repo.CreateJob(context.Background(), "job1", "code", "description")
	assert.NoError(err)
	require.NotNil(job)
	require.NotEmpty(job.PrivateId)

	runs, err := repo.RunJobs(context.Background(), server.PrivateId)
	assert.NoError(err)
	require.Len(runs, 1)
	run := runs[0]
	require.NotEmpty(run.PrivateId)
	assert.Equal(job.PrivateId, run.JobId)

	run, err = repo.UpdateProgress(context.Background(), run.PrivateId, 100, 110)
	assert.NoError(err)
	assert.Equal(uint32(100), run.CompletedCount)
	assert.Equal(uint32(110), run.TotalCount)

	// The only available job is already running, a request for work should return nil
	newRuns, err := repo.RunJobs(context.Background(), server.PrivateId)
	assert.NoError(err)
	require.Len(newRuns, 0)

	run, err = repo.CompleteRun(context.Background(), run.PrivateId, time.Hour)
	assert.NoError(err)
	assert.Equal(Completed.string(), run.Status)

	job, err = repo.LookupJob(context.Background(), job.PrivateId)
	assert.NoError(err)
	require.NotNil(job)

	// The only available job has a next run in the future, a request for work should return nil
	newRuns, err = repo.RunJobs(context.Background(), server.PrivateId)
	assert.NoError(err)
	require.Len(newRuns, 0)

	// Update job next run to time in past
	job.NextScheduledRun = &timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}
	count, err := rw.Update(context.Background(), job, []string{"NextScheduledRun"}, nil)
	require.NoError(err)
	require.Equal(1, count)

	// Now that next scheduled time is in past, a request for work should return a Run
	newRuns, err = repo.RunJobs(context.Background(), server.PrivateId)
	assert.NoError(err)
	require.Len(newRuns, 1)
	newRun := newRuns[0]
	require.NotEmpty(newRun.PrivateId)
	assert.Equal(job.PrivateId, newRun.JobId)
	assert.NotEqual(run.PrivateId, newRun.PrivateId)
}
