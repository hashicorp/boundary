package job

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

// RegisterJobs registers kms related jobs with the provided scheduler.
func RegisterJobs(ctx context.Context, s *scheduler.Scheduler, kmsRepo *kms.Kms) error {
	const op = "kmsjob.RegisterJobs"

	for _, tableName := range kms.ListTablesSupportingRewrap() {
		tableRewrappingJob, err := newTableRewrappingJob(ctx, kmsRepo, tableName)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := s.RegisterJob(ctx, tableRewrappingJob); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	return nil
}
