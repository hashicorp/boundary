package job

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobWorkflow(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)

	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)

	job, err := repo.CreateJob(context.Background(), "job1", "description")
	require.NoError(err)
	require.NotNil(job)
	assert.Equal(defaultPluginId, job.PluginId)

	runs, err := repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	assert.Len(runs, 1)
	run := runs[0]
	assert.NotEmpty(run.PrivateId)
	assert.Equal(job.Name, run.JobName)

	run, err = repo.UpdateProgress(context.Background(), run.PrivateId, 100, 110)
	require.NoError(err)
	assert.Equal(uint32(100), run.CompletedCount)
	assert.Equal(uint32(110), run.TotalCount)

	// The only available job is already running, a request for work should return nil
	newRuns, err := repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	assert.Nil(newRuns)

	run, err = repo.CompleteRun(context.Background(), run.PrivateId, time.Hour, 0, 0)
	require.NoError(err)
	assert.Equal(Completed.string(), run.Status)

	job, err = repo.LookupJob(context.Background(), job.Name)
	require.NoError(err)
	assert.NotNil(job)

	// The only available job has a next run in the future, a request for work should return nil
	newRuns, err = repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	assert.Nil(newRuns)

	// Update job next run to time in past
	job, err = repo.UpdateJobNextRunInAtLeast(context.Background(), job.Name, 0)
	require.NoError(err)

	// Now that next scheduled time is in past, a request for work should return a Run
	newRuns, err = repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	require.Len(newRuns, 1)
	newRun := newRuns[0]
	require.NotEmpty(newRun.PrivateId)
	assert.Equal(job.Name, newRun.JobName)
	assert.NotEqual(run.PrivateId, newRun.PrivateId)

	// The only available job is already running, a request for work should return nil
	newRuns, err = repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	assert.Nil(newRuns)

	newRun, err = repo.FailRun(context.Background(), newRun.PrivateId, 0, 0)
	require.NoError(err)
	assert.Equal(Failed.string(), newRun.Status)

	// Run failed so the job should be available for work immediately
	newRuns, err = repo.RunJobs(context.Background(), server.PrivateId)
	require.NoError(err)
	assert.Len(newRuns, 1)
}

// TODO (LCR): This test can be dropped once plugin support is plumbed through job repo and scheduler
func TestPlugin(t *testing.T) {
	t.Parallel()
	t.Run("plugin-unique", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)

		rows, err := rw.Query(context.Background(), createJobQuery, []interface{}{
			defaultPluginId,
			"same-job-name",
			"description",
			0,
		})
		require.NoError(err)
		_ = rows.Close()

		// Creating a job with same name and pluginId should return a unique constraint error
		rows, err = rw.Query(context.Background(), createJobQuery, []interface{}{
			defaultPluginId,
			"same-job-name",
			"description",
			0,
		})
		require.Error(err)
		assert.Nil(rows)
		assert.Equal("pq: duplicate key value violates unique constraint \"job_pkey\"", err.Error())

		// Create test plugin id
		testPluginId := "pi_test1234"
		numRows, err := rw.Exec(context.Background(), "insert into plugin(public_id) values (?)", []interface{}{testPluginId})
		require.NoError(err)
		assert.Equal(1, numRows)

		// Creating the a job with the same name and different pluginId should succeed
		rows, err = rw.Query(context.Background(), createJobQuery, []interface{}{
			testPluginId,
			"same-job-name",
			"description",
			0,
		})
		assert.NoError(err)
		_ = rows.Close()

		// Creating a job with same name and pluginId should again return a unique constraint error
		rows, err = rw.Query(context.Background(), createJobQuery, []interface{}{
			testPluginId,
			"same-job-name",
			"description",
			0,
		})
		require.Error(err)
		assert.Nil(rows)
		assert.Equal("pq: duplicate key value violates unique constraint \"job_pkey\"", err.Error())
	})
	t.Run("plugin-id-immutable", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)

		// Create test plugin id
		testPluginId := "pi_test1234"
		numRows, err := rw.Exec(context.Background(), "insert into plugin(public_id) values (?)", []interface{}{testPluginId})
		assert.NoError(err)
		assert.Equal(1, numRows)

		newPluginId := "pi_newtest1234"
		numUpdated, err := rw.Exec(context.Background(), "update plugin set public_id = ? where public_id = ?", []interface{}{newPluginId, testPluginId})
		require.Error(err)
		assert.Equal("db.Exec: immutable column: plugin.public_id: integrity violation: error #1003", err.Error())
		assert.Equal(0, numUpdated)
	})
	t.Run("default-plugin-deletion-disallowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)

		numDeleted, err := rw.Exec(context.Background(), "delete from plugin where public_id = ?", []interface{}{defaultPluginId})
		require.Error(err)
		assert.Equal("db.Exec: deletion of system plugin not allowed: integrity violation: error #1104", err.Error())
		assert.Equal(0, numDeleted)

		// Create test plugin id
		testPluginId := "pi_test1234"
		numRows, err := rw.Exec(context.Background(), "insert into plugin(public_id) values (?)", []interface{}{testPluginId})
		assert.NoError(err)
		assert.Equal(1, numRows)

		numDeleted, err = rw.Exec(context.Background(), "delete from plugin where public_id = ?", []interface{}{testPluginId})
		assert.NoError(err)
		assert.Equal(1, numDeleted)
	})
}
