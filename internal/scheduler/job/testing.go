// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

func testJob(t testing.TB, conn *db.DB, name, description string, wrapper wrapping.Wrapper, opt ...Option) *Job {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)

	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	job, err := repo.UpsertJob(ctx, name, description, opt...)
	require.NoError(err)
	require.NotNil(job)

	return job
}

func testRun(conn *db.DB, pluginId, name, cId string) (*Run, error) {
	query := `
		insert into job_run (
			job_plugin_id, job_name, controller_id
		)
		values (?,?,?)
		on conflict (job_plugin_id, job_name) where status = 'running'
	    do nothing
		returning *;
	`
	rw := db.New(conn)
	run := allocRun()
	ctx := context.Background()
	rows, err := rw.Query(ctx, query, []any{pluginId, name, cId})
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, nil
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	err = rw.ScanRows(ctx, rows, run)
	if err != nil {
		return nil, err
	}
	_ = rows.Close()

	return run, nil
}

func testRunWithUpdateTime(conn *db.DB, pluginId, name, cId string, updateTime time.Time) (*Run, error) {
	query := `
		insert into job_run (
		  job_plugin_id, job_name, controller_id, update_time
		)
		values (?,?,?,?)
		returning *;
	`
	rw := db.New(conn)
	run := allocRun()
	ctx := context.Background()
	rows, err := rw.Query(ctx, query, []any{pluginId, name, cId, updateTime})
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, fmt.Errorf("expected to rows")
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	err = rw.ScanRows(ctx, rows, run)
	if err != nil {
		return nil, err
	}
	_ = rows.Close()

	return run, nil
}

func testController(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper, opt ...testOption) *server.Controller {
	t.Helper()
	ctx := context.Background()
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	opts := getTestOpts(t, opt...)

	privateId := opts.controllerId
	if privateId == "" {
		// generate a unique ID for the test
		id, err := uuid.GenerateUUID()
		require.NoError(t, err)
		privateId = "test-job-server-" + id
	}
	controller := server.NewController(privateId, server.WithAddress("127.0.0.1"))
	_, err = serversRepo.UpsertController(ctx, controller)
	require.NoError(t, err)
	return controller
}

func getTestOpts(t testing.TB, opt ...testOption) testOptions {
	t.Helper()
	opts := getDefaultTestOptions(t)
	for _, o := range opt {
		o(t, &opts)
	}
	return opts
}

// testOption - how Options are passed as arguments.
type testOption func(testing.TB, *testOptions)

// options = how options are represented
type testOptions struct {
	controllerId string
}

func getDefaultTestOptions(t testing.TB) testOptions {
	t.Helper()

	return testOptions{
		controllerId: "",
	}
}

// withControllerId sets the controller id
func withControllerId(p string) testOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.controllerId = p
	}
}
