package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func testScheduler(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, serverId string, opts ...Option) *Scheduler {
	t.Helper()

	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(rw, rw, kmsCache)
	}

	s, err := New(serverId, jobRepoFn, hclog.L(), opts...)
	require.NoError(t, err)
	return s
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

type testJob struct {
	nextRunIn         time.Duration
	name, description string
	fn                func(context.Context) error
}

func (j testJob) Status() JobStatus {
	return JobStatus{}
}

func (j testJob) Run(ctx context.Context) error {
	return j.fn(ctx)
}

func (j testJob) NextRunIn() time.Duration {
	return j.nextRunIn
}

func (j testJob) Name() string {
	return j.name
}

func (j testJob) Description() string {
	return j.description
}
