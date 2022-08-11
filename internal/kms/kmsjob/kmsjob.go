package kmsjob

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

// RegisterJobs registers kms related jobs with the provided scheduler.
func RegisterJobs(ctx context.Context, s *scheduler.Scheduler, k *kms.Kms) error {
	const op = "kmsjob.RegisterJobs"

	revokeKeyJob, err := newRevokeKeyJob(ctx, k)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err = s.RegisterJob(ctx, revokeKeyJob); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}
