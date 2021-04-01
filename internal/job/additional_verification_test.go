package job

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobWorkflow(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	server := testController(t, conn, wrapper)

	repo, err := NewRepository(rw, rw, kms)
	assert.NoError(err)

	job, err := NewJob("job1", "code", "description")
	assert.NoError(err)

	job, err = repo.CreateJob(context.Background(), job)
	assert.NoError(err)
	require.NotEmpty(job.PrivateId)

	run, err := repo.FetchWork(context.Background(), server.PrivateId)
	assert.NoError(err)
	require.NotNil(run)
	require.NotEmpty(run.PrivateId)
	assert.Equal(job.PrivateId, run.JobId)

	run.TotalCount = 110
	run.CompletedCount = 100

	run, count, err := repo.CheckpointJobRun(context.Background(), run, []string{"TotalCount", "CompletedCount"})
	assert.NoError(err)
	assert.Equal(1, count)

	// The only available job is already running, a request for work should return nil
	newRun, err := repo.FetchWork(context.Background(), server.PrivateId)
	assert.NoError(err)
	require.Nil(newRun)

	err = repo.EndJobRun(context.Background(), run.PrivateId, Completed, testFutureTime)
	assert.NoError(err)

	job, err = repo.LookupJob(context.Background(), job.PrivateId)
	assert.NoError(err)
	require.NotNil(job)
	assert.Equal(testFutureTime, job.NextScheduledRun)

	// The only available job has a next run in the future, a request for work should return nil
	newRun, err = repo.FetchWork(context.Background(), server.PrivateId)
	assert.NoError(err)
	require.Nil(newRun)

	// Update job next run to time in past
	job.NextScheduledRun = testZeroTime
	job, count, err = repo.UpdateJob(context.Background(), job, []string{"NextScheduledRun"})

	// Now that next scheduled time is in past request for work should return a JobRun
	newRun, err = repo.FetchWork(context.Background(), server.PrivateId)
	assert.NoError(err)
	require.NotNil(newRun)
	require.NotEmpty(newRun.PrivateId)
	assert.Equal(job.PrivateId, newRun.JobId)
	assert.NotEqual(run.PrivateId, newRun.PrivateId)
}
