// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"database/sql"
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
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	server := testController(t, conn, wrapper)

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	job, err := repo.UpsertJob(ctx, "job1", "description")
	require.NoError(err)
	require.NotNil(job)
	assert.Equal(defaultPluginId, job.PluginId)

	runs, err := repo.RunJobs(ctx, server.PrivateId)
	require.NoError(err)
	assert.Len(runs, 1)
	run := runs[0]
	assert.NotEmpty(run.PrivateId)
	assert.Equal(job.Name, run.JobName)

	run, err = repo.UpdateProgress(ctx, run.PrivateId, 100, 110, 0)
	require.NoError(err)
	assert.Equal(uint32(100), run.CompletedCount)
	assert.Equal(uint32(110), run.TotalCount)

	// The only available job is already running, a request for work should return nil
	newRuns, err := repo.RunJobs(ctx, server.PrivateId)
	require.NoError(err)
	assert.Nil(newRuns)

	err = repo.CompleteRun(ctx, run.PrivateId, time.Hour)
	require.NoError(err)

	job, err = repo.LookupJob(ctx, job.Name)
	require.NoError(err)
	assert.NotNil(job)

	// The only available job has a next run in the future, a request for work should return nil
	newRuns, err = repo.RunJobs(ctx, server.PrivateId)
	require.NoError(err)
	assert.Nil(newRuns)

	// Update job next run to time in past
	job, err = repo.UpdateJobNextRunInAtLeast(ctx, job.Name, 0)
	require.NoError(err)

	// Now that next scheduled time is in past, a request for work should return a Run
	newRuns, err = repo.RunJobs(ctx, server.PrivateId)
	require.NoError(err)
	require.Len(newRuns, 1)
	newRun := newRuns[0]
	require.NotEmpty(newRun.PrivateId)
	assert.Equal(job.Name, newRun.JobName)
	assert.NotEqual(run.PrivateId, newRun.PrivateId)

	// The only available job is already running, a request for work should return nil
	newRuns, err = repo.RunJobs(ctx, server.PrivateId)
	require.NoError(err)
	assert.Nil(newRuns)

	newRun, err = repo.FailRun(ctx, newRun.PrivateId, 0, 0, 0)
	require.NoError(err)
	assert.Equal(Failed.string(), newRun.Status)

	// Run failed so the job should be available for work immediately
	newRuns, err = repo.RunJobs(ctx, server.PrivateId)
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

		rows, err := rw.Query(context.Background(), upsertJobQuery, []any{
			sql.Named("plugin_id", defaultPluginId),
			sql.Named("name", "same-job-name"),
			sql.Named("description", "description"),
			sql.Named("next_scheduled_run", 0),
		})
		require.NoError(err)
		_ = rows.Close()

		rows, err = rw.Query(context.Background(), "select * from job;", nil)
		require.NoError(err)
		var numRows int
		for rows.Next() {
			numRows++
		}
		require.NoError(rows.Err())
		_ = rows.Close()
		require.Equal(1, numRows)

		// Calling upsertJob with same name and pluginId should not insert a new job
		rows, err = rw.Query(context.Background(), upsertJobQuery, []any{
			sql.Named("plugin_id", defaultPluginId),
			sql.Named("name", "same-job-name"),
			sql.Named("description", "description"),
			sql.Named("next_scheduled_run", 0),
		})
		require.NoError(err)
		_ = rows.Close()

		// Validate there is still only 1 job in the database
		rows, err = rw.Query(context.Background(), "select * from job;", nil)
		require.NoError(err)
		numRows = 0
		for rows.Next() {
			numRows++
		}
		require.NoError(rows.Err())
		_ = rows.Close()
		require.Equal(1, numRows)

		// Create test plugin id
		testPluginId := "pi_test1234"
		numRows, err = rw.Exec(context.Background(), "insert into plugin(public_id, scope_id) values (?, 'global')", []any{testPluginId})
		require.NoError(err)
		assert.Equal(1, numRows)

		// Calling upsertJob with the same name and different pluginId should create a new job
		rows, err = rw.Query(context.Background(), upsertJobQuery, []any{
			sql.Named("plugin_id", testPluginId),
			sql.Named("name", "same-job-name"),
			sql.Named("description", "description"),
			sql.Named("next_scheduled_run", 0),
		})
		assert.NoError(err)
		_ = rows.Close()

		// Validate there are 2 jobs in the database
		rows, err = rw.Query(context.Background(), "select * from job;", nil)
		require.NoError(err)
		numRows = 0
		for rows.Next() {
			numRows++
		}
		require.NoError(rows.Err())
		_ = rows.Close()
		require.Equal(2, numRows)
	})
	t.Run("plugin-id-immutable", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)

		// Create test plugin id
		testPluginId := "pi_test1234"
		numRows, err := rw.Exec(context.Background(), "insert into plugin(public_id, scope_id) values (?, 'global')", []any{testPluginId})
		assert.NoError(err)
		assert.Equal(1, numRows)

		newPluginId := "pi_newtest1234"
		numUpdated, err := rw.Exec(context.Background(), "update plugin set public_id = ? where public_id = ?", []any{newPluginId, testPluginId})
		require.Error(err)
		assert.Equal("db.Exec: immutable column: plugin.public_id: integrity violation: error #1003", err.Error())
		assert.Equal(0, numUpdated)
	})
	t.Run("default-plugin-deletion-disallowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)

		numDeleted, err := rw.Exec(context.Background(), "delete from plugin where public_id = ?", []any{defaultPluginId})
		require.Error(err)
		assert.Equal("db.Exec: deletion of system plugin not allowed: integrity violation: error #1104", err.Error())
		assert.Equal(0, numDeleted)

		// Create test plugin id
		testPluginId := "pi_test1234"
		numRows, err := rw.Exec(context.Background(), "insert into plugin(public_id, scope_id) values (?, 'global')", []any{testPluginId})
		assert.NoError(err)
		assert.Equal(1, numRows)

		numDeleted, err = rw.Exec(context.Background(), "delete from plugin where public_id = ?", []any{testPluginId})
		assert.NoError(err)
		assert.Equal(1, numDeleted)
	})
}
