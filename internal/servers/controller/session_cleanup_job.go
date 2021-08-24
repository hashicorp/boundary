package controller

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/session"
)

// sessionCleanupJob defines a periodic job that monitors workers for
// loss of connection and terminates connections on workers that have
// not sent a heartbeat in a significant period of time.
//
// Relevant connections are simply marked as disconnected in the
// database. Connections will be independently terminated by the
// worker, or the event of a synchronization issue between the two,
// the controller will win out and order that the connections be
// closed on the worker.
type sessionCleanupJob struct {
	sessionRepoFn common.SessionRepoFactory

	// The amount of time to give disconnected workers before marking
	// their connections as closed.
	gracePeriod int

	// The total number of connections closed in the last run.
	totalClosed int
}

// newSessionCleanupJob instantiates the session cleanup job.
func newSessionCleanupJob(
	sessionRepoFn common.SessionRepoFactory,
	gracePeriod int,
) (*sessionCleanupJob, error) {
	const op = "controller.newNewSessionCleanupJob"
	switch {
	case sessionRepoFn == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing sessionRepoFn")
	case gracePeriod < session.DeadWorkerConnCloseMinGrace:
		return nil, errors.NewDeprecated(
			errors.InvalidParameter, op, fmt.Sprintf("invalid gracePeriod, must be greater than %d", session.DeadWorkerConnCloseMinGrace))
	}

	return &sessionCleanupJob{
		sessionRepoFn: sessionRepoFn,
		gracePeriod:   gracePeriod,
	}, nil
}

// Name returns a short, unique name for the job.
func (j *sessionCleanupJob) Name() string { return "session_cleanup" }

// Description returns the description for the job.
func (j *sessionCleanupJob) Description() string {
	return "Clean up session connections from disconnected workers"
}

// NextRunIn returns the next run time after a job is completed.
//
// The next run time is defined for sessionCleanupJob as one second.
// This is because the job should run continuously to terminate
// connections as soon as a worker has not reported in for a long
// enough time. Only one job will ever run at once, so there is no
// reason why it cannot run again immediately.
func (j *sessionCleanupJob) NextRunIn() (time.Duration, error) { return time.Second, nil }

// Status returns the status of the running job.
func (j *sessionCleanupJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: j.totalClosed,
		Total:     j.totalClosed,
	}
}

// Run executes the job.
func (j *sessionCleanupJob) Run(ctx context.Context) error {
	const op = "controller.(sessionCleanupJob).Run"
	j.totalClosed = 0

	// Load repos.
	sessionRepo, err := j.sessionRepoFn()
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error getting session repo"))
	}

	// Run the atomic dead worker cleanup job.
	results, err := sessionRepo.CloseConnectionsForDeadWorkers(ctx, j.gracePeriod)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if len(results) < 1 {
	} else {
		for _, result := range results {
			event.WriteError(ctx, op, stderrors.New("worker has not reported status within acceptable grace period, all connections closed"),
				event.WithInfo(
					"private_id", result.ServerId,
					"update_time", result.LastUpdateTime,
					"grace_period_seconds", j.gracePeriod,
					"number_connections_closed", result.NumberConnectionsClosed,
				))

			j.totalClosed += result.NumberConnectionsClosed
		}
	}

	return nil
}
