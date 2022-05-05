package session

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/scheduler"
)

// RegisterJobs registers plugin host related jobs with the provided scheduler.
func RegisterJobs(ctx context.Context, scheduler *scheduler.Scheduler, w db.Writer, gracePeriod time.Duration) error {
	const op = "session.RegisterJobs"
	sessionConnectionCleanupJob, err := newSessionConnectionCleanupJob(w, gracePeriod)
	if err != nil {
		return fmt.Errorf("error creating session cleanup job: %w", err)
	}
	if err = scheduler.RegisterJob(ctx, sessionConnectionCleanupJob); err != nil {
		return fmt.Errorf("error registering session cleanup job: %w", err)
	}

	return nil
}
