package job

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func testJob(t *testing.T, conn *gorm.DB, name, code, description string, opt ...Option) *Job {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)

	job, err := NewJob(name, code, description, opt...)
	require.NoError(err)

	id, err := newJobId(name, job.Code)
	require.NoError(err)
	job.PrivateId = id
	err = rw.Create(context.Background(), job)
	require.NoError(err)

	return job
}

func testJobRun(t *testing.T, conn *gorm.DB, jId, cId string, opt ...Option) *JobRun {
	t.Helper()
	require := require.New(t)

	rw := db.New(conn)

	run, err := NewJobRun(jId, cId, opt...)
	require.NoError(err)

	err = rw.Create(context.Background(), run)
	require.NoError(err)

	return run
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
