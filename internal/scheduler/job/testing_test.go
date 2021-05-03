package job

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestJob(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "testJob", "testDescription", wrapper)
	require.NotNil(job)

	rw := db.New(conn)
	var got Job
	err := rw.LookupWhere(context.Background(), &got, "name = ?", job.Name)
	require.NoError(err)
	assert.Equal("testJob", got.Name)
	assert.Equal("testDescription", got.Description)
	assert.Equal(defaultPluginId, got.PluginId)
	assert.NotEmpty(got.NextScheduledRun)

	job1 := testJob(t, conn, "testJob1", "testDescription1", wrapper, WithNextRunIn(time.Hour))
	require.NotNil(job1)

	var got1 Job
	err = rw.LookupWhere(context.Background(), &got1, "name = ?", job1.Name)
	require.NoError(err)
	assert.Equal("testJob1", got1.Name)
	assert.Equal("testDescription1", got1.Description)
	assert.Equal(defaultPluginId, got.PluginId)
	assert.NotEmpty(got1.NextScheduledRun)

	// The previous job next scheduled run should have been created with the current database time,
	// while the current job should be an hour later
	previousJobNextRun := got.NextScheduledRun.Timestamp.GetSeconds()
	currentJobNextRun := got1.NextScheduledRun.Timestamp.GetSeconds()
	nextRunIn := int64(time.Hour.Seconds())
	assert.True(currentJobNextRun >= previousJobNextRun+nextRunIn,
		fmt.Sprintf("expected next run (%d) to be greater than or equal to the previous run end time (%d) incremented by %d",
			currentJobNextRun, previousJobNextRun, nextRunIn))
}

func Test_TestRun(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iam.TestRepo(t, conn, wrapper)

	job := testJob(t, conn, "testJob", "testDescription", wrapper)
	require.NotNil(job)

	server := testController(t, conn, wrapper)

	run, err := testRun(conn, job.PluginId, job.Name, server.PrivateId)
	require.NoError(err)
	require.NotNil(run)

	rw := db.New(conn)
	var got Run
	err = rw.LookupWhere(context.Background(), &got, "private_id = ?", run.PrivateId)
	require.NoError(err)
	assert.Equal(server.PrivateId, got.ServerId)
	assert.Equal(job.Name, got.JobName)
	assert.Equal(job.PluginId, got.JobPluginId)
	assert.NotEmpty(got.CreateTime)
	assert.Equal(Running.string(), got.Status)
}
