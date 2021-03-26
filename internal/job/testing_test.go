package job

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestJob(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")

	job := testJob(t, conn, "testJob", "testCode", "testDescription")
	require.NotNil(job)

	rw := db.New(conn)
	var got Job
	err := rw.LookupWhere(context.Background(), &got, "private_id = ?", job.PrivateId)
	require.NoError(err)
	assert.Equal("testJob", got.Name)
	assert.Equal("testDescription", got.Description)
	assert.Equal("testCode", got.Code)
	assert.Equal(zeroTime.Timestamp, got.NextScheduledRun.Timestamp)

	job1 := testJob(t, conn, "testJob1", "testCode1", "testDescription1", WithNextScheduledRun(futureTime))
	require.NotNil(job1)

	var got1 Job
	err = rw.LookupWhere(context.Background(), &got1, "private_id = ?", job1.PrivateId)
	require.NoError(err)
	assert.Equal("testJob1", got1.Name)
	assert.Equal("testDescription1", got1.Description)
	assert.Equal("testCode1", got1.Code)
	assert.Equal(futureTime.Timestamp, got1.NextScheduledRun.Timestamp)
}

func Test_TestJobRun(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	job := testJob(t, conn, "testJob", "testCode", "testDescription")
	require.NotNil(job)

	server := testController(t, conn, wrapper)

	run := testJobRun(t, conn, job.PrivateId, server.PrivateId)
	require.NotNil(run)

	rw := db.New(conn)
	var got JobRun
	err := rw.LookupWhere(context.Background(), &got, "id = ?", run.Id)
	require.NoError(err)
	assert.Equal(server.PrivateId, got.ServerId)
	assert.Equal(job.PrivateId, got.JobId)
	assert.NotEmpty(got.CreateTime)
	assert.Equal(string(Running), got.Status)

	run1 := testJobRun(t, conn, job.PrivateId, server.PrivateId, WithJobRunStatus(Completed))
	require.NotNil(run1)

	var got1 JobRun
	err = rw.LookupWhere(context.Background(), &got1, "id = ?", run1.Id)
	require.NoError(err)
	assert.Equal(server.PrivateId, got1.ServerId)
	assert.Equal(job.PrivateId, got1.JobId)
	assert.NotEmpty(got1.CreateTime)
	assert.Equal(string(Completed), got1.Status)
}
