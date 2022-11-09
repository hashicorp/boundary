package job

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

type tableRewrappingJob struct {
	kmsRepo   *kms.Kms
	tableName string
}

func newTableRewrappingJob(ctx context.Context, kmsRepo *kms.Kms, tableName string) (*tableRewrappingJob, error) {
	const op = "kms.newTableRewrappingJob"
	if kmsRepo == nil {
		return nil, errors.New(ctx, errors.Internal, "nil kms repo", op, errors.WithoutEvent())
	}
	if tableName == "" {
		return nil, errors.New(ctx, errors.Internal, "no table name provided", op, errors.WithoutEvent())
	}

	return &tableRewrappingJob{
		kmsRepo:   kmsRepo,
		tableName: tableName,
	}, nil
}

// Status reports the job’s current status. We never change these values as
// this job never finishes.
func (d *tableRewrappingJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (r *tableRewrappingJob) Run(ctx context.Context) error {
	const op = "kmsjob.(tableRewrappingJob).Run"

	if err := r.kmsRepo.MonitorTableRewrappingRuns(ctx, r.tableName); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// We report as ready 1 second after a successful run. This doesn't mean that
// this job will run every second, only about as often as the configured scheduler interval.
func (r *tableRewrappingJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return time.Second, nil
}

// Name is the unique name of the job.
func (r *tableRewrappingJob) Name() string {
	return fmt.Sprintf("%s-rewrapping-job", r.tableName)
}

// Description is the human readable description of the job.
func (d *tableRewrappingJob) Description() string {
	return "Re-encrypt all data encrypted in a table using a specific key"
}
