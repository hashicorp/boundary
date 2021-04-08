package job

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func testJob(t *testing.T, conn *gorm.DB, name, code, description string, wrapper wrapping.Wrapper, opt ...Option) *Job {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)

	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)

	job, err := repo.CreateJob(context.Background(), name, code, description, opt...)
	require.NoError(err)
	require.NotNil(job)

	return job
}

var testRunQuery = `
	insert into job_run (
	  job_id, server_id
	)
	values (?,?)
	returning *;
`

func testRun(conn *gorm.DB, jId, cId string) (*Run, error) {
	rw := db.New(conn)
	run := allocRun()

	rows, err := rw.Query(context.Background(), testRunQuery, []interface{}{jId, cId})
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, fmt.Errorf("expected to rows")
	}

	err = rw.ScanRows(rows, run)
	if err != nil {
		return nil, err
	}
	_ = rows.Close()

	return run, nil
}

func testController(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper) *servers.Server {
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
