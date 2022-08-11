package kmsjob

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

type revokeKeyJob struct {
	kmsRepo *kms.Kms

	// the number of rows processed in the current job
	rowsProcessed int
}

func newRevokeKeyJob(ctx context.Context, kmsRepo *kms.Kms) (*revokeKeyJob, error) {
	const op = "kms.newRevokeKeyJob"
	if kmsRepo == nil {
		return nil, errors.New(ctx, errors.Internal, "nil kms repo", op, errors.WithoutEvent())
	}

	return &revokeKeyJob{
		kmsRepo: kmsRepo,
	}, nil
}

// Status reports the job’s current status.  The status is periodically persisted by
// the scheduler when a job is running, and will be used to verify a job is making progress.
func (d *revokeKeyJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: d.rowsProcessed,
		Total:     d.rowsProcessed,
	}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (r *revokeKeyJob) Run(ctx context.Context) error {
	const op = "kmsjob.(revokeKeyJob).Run"

	revocations, err := r.kmsRepo.ListKeyRevocations(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// First check if there is already a revocation in progress
	for _, revocation := range revocations {
		if revocation.Status == kms.KeyRevocationStatusRunning.String() {
			// Revocation is already in progress, try again next time
			return nil
		}
	}

	// See if there are any pending revocations we can start
	for _, revocation := range revocations {
		if revocation.Status == kms.KeyRevocationStatusPending.String() {
			if err := r.kmsRepo.RunKeyRevocation(ctx, revocation); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		}
	}

	// Nothing to do, try again next time
	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// We run every 10 seconds to be somewhat responsive to user requests.
func (r *revokeKeyJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 10 * time.Second, nil
}

// Name is the unique name of the job.
func (r *revokeKeyJob) Name() string {
	return "revoke-key"
}

// Description is the human readable description of the job.
func (d *revokeKeyJob) Description() string {
	return "Revoke a key and reencrypt all data encrypted using that key"
}
