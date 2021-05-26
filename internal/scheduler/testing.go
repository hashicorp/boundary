package scheduler

import (
	"context"
	"sync"
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

func TestScheduler(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, opt ...Option) *Scheduler {
	t.Helper()

	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrapper)
	serversRepo, err := servers.NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)
	iam.TestRepo(t, conn, wrapper)

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

	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(rw, rw, kmsCache)
	}

	s, err := New(controller.PrivateId, jobRepoFn, hclog.L(), opt...)
	require.NoError(t, err)

	return s
}

func testJobFn() (func(ctx context.Context) error, chan struct{}, chan struct{}) {
	jobReady := make(chan struct{})
	jobDone := make(chan struct{})
	fn := func(ctx context.Context) error {
		jobReady <- struct{}{}

		// Block until context is canceled
		<-ctx.Done()

		jobDone <- struct{}{}
		return nil
	}
	return fn, jobReady, jobDone
}

type testJob struct {
	nextRunIn         time.Duration
	name, description string
	fn                func(context.Context) error
	statusFn          func() JobStatus
}

func (j testJob) Status() JobStatus {
	if j.statusFn == nil {
		return JobStatus{}
	}
	return j.statusFn()
}

func (j testJob) Run(ctx context.Context) error {
	return j.fn(ctx)
}

func (j testJob) NextRunIn() (time.Duration, error) {
	return j.nextRunIn, nil
}

func (j testJob) Name() string {
	return j.name
}

func (j testJob) Description() string {
	return j.description
}

func mapLen(sm *sync.Map) int {
	count := 0
	sm.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}
