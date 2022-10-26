package job

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

type dataKeyVersionDestructionMonitorJob struct {
	kmsRepo *kms.Kms
}

func newDataKeyVersionDestructionMonitorJob(ctx context.Context, kmsRepo *kms.Kms) (*dataKeyVersionDestructionMonitorJob, error) {
	const op = "kms.newDataKeyVersionDestructionMonitorJob"
	if kmsRepo == nil {
		return nil, errors.New(ctx, errors.Internal, "nil kms repo", op, errors.WithoutEvent())
	}

	return &dataKeyVersionDestructionMonitorJob{
		kmsRepo: kmsRepo,
	}, nil
}

// Status reports the job’s current status. We never change these values as
// this job never finishes.
func (d *dataKeyVersionDestructionMonitorJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (r *dataKeyVersionDestructionMonitorJob) Run(ctx context.Context) error {
	const op = "kmsjob.(dataKeyVersionDestructionMonitorJob).Run"

	if err := r.kmsRepo.MonitorDataKeyVersionDestruction(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// We report as ready 1 second after a successful run. This doesn't mean that
// this job will run every second, only about as often as the configured scheduler interval.
func (r *dataKeyVersionDestructionMonitorJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return time.Second, nil
}

// Name is the unique name of the job.
func (r *dataKeyVersionDestructionMonitorJob) Name() string {
	return "data-key-version-destruction-monitor-job"
}

// Description is the human readable description of the job.
func (d *dataKeyVersionDestructionMonitorJob) Description() string {
	return "Destroy a key version once all data has been rewrapped"
}
