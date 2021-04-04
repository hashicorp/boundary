package job

import (
	"context"
	"testing"
	"time"

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
	assert.Equal(testZeroTime.Timestamp.GetSeconds(), got.NextScheduledRun.Timestamp.GetSeconds())

	nextRun := time.Now().Add(time.Hour)
	job1 := testJob(t, conn, "testJob1", "testCode1", "testDescription1", WithNextScheduledRun(nextRun))
	require.NotNil(job1)

	var got1 Job
	err = rw.LookupWhere(context.Background(), &got1, "private_id = ?", job1.PrivateId)
	require.NoError(err)
	assert.Equal("testJob1", got1.Name)
	assert.Equal("testDescription1", got1.Description)
	assert.Equal("testCode1", got1.Code)
	assert.Equal(nextRun.Unix(), got1.NextScheduledRun.Timestamp.GetSeconds())
}

func Test_TestJobRun(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	job := testJob(t, conn, "testJob", "testCode", "testDescription")
	require.NotNil(job)

	server := testController(t, conn, wrapper)

	run := testJobRun(t, conn, job.PrivateId, server.PrivateId, Running)
	require.NotNil(run)

	rw := db.New(conn)
	var got JobRun
	err := rw.LookupWhere(context.Background(), &got, "private_id = ?", run.PrivateId)
	require.NoError(err)
	assert.Equal(server.PrivateId, got.ServerId)
	assert.Equal(job.PrivateId, got.JobId)
	assert.NotEmpty(got.CreateTime)
	assert.Equal(Running.String(), got.Status)

	run1 := testJobRun(t, conn, job.PrivateId, server.PrivateId, Completed)
	require.NotNil(run1)

	var got1 JobRun
	err = rw.LookupWhere(context.Background(), &got1, "private_id = ?", run1.PrivateId)
	require.NoError(err)
	assert.Equal(server.PrivateId, got1.ServerId)
	assert.Equal(job.PrivateId, got1.JobId)
	assert.NotEmpty(got1.CreateTime)
	assert.Equal(Completed.String(), got1.Status)
}
