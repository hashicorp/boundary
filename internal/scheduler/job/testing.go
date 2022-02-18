package job

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

func testJob(t *testing.T, conn *db.DB, name, description string, wrapper wrapping.Wrapper, opt ...Option) *Job {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)

	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)

	job, err := repo.UpsertJob(context.Background(), name, description, opt...)
	require.NoError(err)
	require.NotNil(job)

	return job
}

func testRun(conn *db.DB, pluginId, name, cId string) (*Run, error) {
	query := `
		insert into job_run (
			job_plugin_id, job_name, server_id
		)
		values (?,?,?)
		returning *;
	`
	rw := db.New(conn)
	run := allocRun()
	ctx := context.Background()
	rows, err := rw.Query(ctx, query, []interface{}{pluginId, name, cId})
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, fmt.Errorf("expected to rows")
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
		  job_plugin_id, job_name, server_id, update_time
		)
		values (?,?,?,?)
		returning *;
	`
	rw := db.New(conn)
	run := allocRun()
	ctx := context.Background()
	rows, err := rw.Query(ctx, query, []interface{}{pluginId, name, cId, updateTime})
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, fmt.Errorf("expected to rows")
	}

	err = rw.ScanRows(ctx, rows, run)
	if err != nil {
		return nil, err
	}
	_ = rows.Close()

	return run, nil
}

func testController(t *testing.T, conn *db.DB, wrapper wrapping.Wrapper) *servers.Server {
	t.Helper()
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	controller := &servers.Server{
		PrivateId:   "test-job-server-" + id,
		Type:        servers.ServerTypeController.String(),
		Description: "Test Job Controller",
		Address:     "127.0.0.1",
	}
	_, _, err = serversRepo.UpsertServer(context.Background(), controller)
	require.NoError(t, err)
	return controller
}
