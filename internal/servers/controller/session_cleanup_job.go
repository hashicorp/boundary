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

// sessionConnectionCleanupJob defines a periodic job that monitors workers for
// loss of connection and terminates connections on workers that have
// not sent a heartbeat in a significant period of time.
//
// Relevant connections are simply marked as disconnected in the
// database. Connections will be independently terminated by the
// worker, or the event of a synchronization issue between the two,
// the controller will win out and order that the connections be
// closed on the worker.
type sessionConnectionCleanupJob struct {
	connectionRepoFn common.ConnectionRepoFactory

	// The amount of time to give disconnected workers before marking
	// their connections as closed.
	gracePeriod int

	// The total number of connections closed in the last run.
	totalClosed int
}

// newSessionConnectionCleanupJob instantiates the session cleanup job.
func newSessionConnectionCleanupJob(
	connectionRepoFn common.ConnectionRepoFactory,
	gracePeriod int,
) (*sessionConnectionCleanupJob, error) {
	const op = "controller.newNewSessionConnectionCleanupJob"
	switch {
	case connectionRepoFn == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing connectionRepoFn")
	case gracePeriod < session.DeadWorkerConnCloseMinGrace:
		return nil, errors.NewDeprecated(
			errors.InvalidParameter, op, fmt.Sprintf("invalid gracePeriod, must be greater than %d", session.DeadWorkerConnCloseMinGrace))
	}

	return &sessionConnectionCleanupJob{
		connectionRepoFn: connectionRepoFn,
		gracePeriod:      gracePeriod,
	}, nil
}

// Name returns a short, unique name for the job.
func (j *sessionConnectionCleanupJob) Name() string { return "session_cleanup" }

// Description returns the description for the job.
func (j *sessionConnectionCleanupJob) Description() string {
	return "Clean up session connections from disconnected workers"
}

// NextRunIn returns the next run time after a job is completed.
//
// The next run time is defined for sessionConnectionCleanupJob as one second.
// This is because the job should run continuously to terminate
// connections as soon as a worker has not reported in for a long
// enough time. Only one job will ever run at once, so there is no
// reason why it cannot run again immediately.
func (j *sessionConnectionCleanupJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return time.Second, nil
}

// Status returns the status of the running job.
func (j *sessionConnectionCleanupJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: j.totalClosed,
		Total:     j.totalClosed,
	}
}

// Run executes the job.
func (j *sessionConnectionCleanupJob) Run(ctx context.Context) error {
	const op = "controller.(sessionConnectionCleanupJob).Run"
	j.totalClosed = 0

	// Load repos.
	connectionRepo, err := j.connectionRepoFn()
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error getting session repo"))
	}

	// Run the atomic dead worker cleanup job.
	results, err := connectionRepo.CloseConnectionsForDeadWorkers(ctx, j.gracePeriod)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

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

	return nil
}
