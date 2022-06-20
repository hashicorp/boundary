package session

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
)

// deadWorkerConnCloseMinGrace is the minimum allowable setting for
// the closeConnectionsForDeadWorkers method. This is synced with
// the default server liveness setting.
const deadWorkerConnCloseMinGrace = server.DefaultLiveness

type closeConnectionsForDeadWorkersResult struct {
	WorkerId                string
	LastUpdateTime          time.Time
	NumberConnectionsClosed int
}

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
	writer db.Writer

	// The amount of time to give disconnected workers before marking
	// their connections as closed.  This should be at larger than the liveness
	// setting for the worker.
	gracePeriod time.Duration

	// The total number of connections closed in the last run.
	totalClosed int
}

// newSessionConnectionCleanupJob instantiates the session cleanup job.
func newSessionConnectionCleanupJob(
	writer db.Writer,
	gracePeriod time.Duration,
) (*sessionConnectionCleanupJob, error) {
	const op = "session.newNewSessionConnectionCleanupJob"
	switch {
	case writer == nil:
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing db writer")
	case gracePeriod < deadWorkerConnCloseMinGrace:
		return nil, errors.NewDeprecated(
			errors.InvalidParameter, op, fmt.Sprintf("invalid gracePeriod, must be greater than %s", deadWorkerConnCloseMinGrace))
	}

	return &sessionConnectionCleanupJob{
		writer:      writer,
		gracePeriod: gracePeriod,
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
	const op = "session.(sessionConnectionCleanupJob).Run"
	j.totalClosed = 0

	// Run the atomic dead worker cleanup job.
	results, err := j.closeConnectionsForDeadWorkers(ctx, j.gracePeriod)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	for _, result := range results {
		event.WriteError(ctx, op, stderrors.New("worker has not reported status within acceptable grace period, all connections closed"),
			event.WithInfo(
				"public_id", result.WorkerId,
				"update_time", result.LastUpdateTime,
				"grace_period_seconds", j.gracePeriod.Seconds(),
				"number_connections_closed", result.NumberConnectionsClosed,
			))

		j.totalClosed += result.NumberConnectionsClosed
	}

	{
		count, err := j.closeWorkerlessConnections(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if count > 0 {
			event.WriteError(ctx, op, stderrors.New("connections with no worker closed"),
				event.WithInfo(
					"number_connections_closed", count,
				))
			j.totalClosed += count
		}
	}

	return nil
}

// closeWorkerlessConnections will close all connections which do not have a
// worker id associated with them.
func (j *sessionConnectionCleanupJob) closeWorkerlessConnections(ctx context.Context) (int, error) {
	const op = "session.(sessionConnectionCleanupJob).closeWorkerlessConnections"
	count := 0
	_, err := j.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			count, err = w.Exec(ctx, closeWorkerlessConnections, []interface{}{})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return count, errors.Wrap(ctx, err, op)
	}

	return count, nil
}

// closeConnectionsForDeadWorkers will run
// closeConnectionsForDeadServersCte to look for connections that
// should be marked because they are on a server that is no longer
// sending status updates to the controller(s).
//
// The only input to the method is the grace period, in seconds.
func (j *sessionConnectionCleanupJob) closeConnectionsForDeadWorkers(ctx context.Context, gracePeriod time.Duration) ([]closeConnectionsForDeadWorkersResult, error) {
	const op = "session.(sessionConnectionCleanupJob).closeConnectionsForDeadWorkers"
	args := []interface{}{
		sql.Named("grace_period_seconds", gracePeriod.Seconds()),
	}
	results := make([]closeConnectionsForDeadWorkersResult, 0)
	_, err := j.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, closeConnectionsForDeadServersCte, args)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			for rows.Next() {
				var result closeConnectionsForDeadWorkersResult
				if err := w.ScanRows(ctx, rows, &result); err != nil {
					return errors.Wrap(ctx, err, op)
				}

				results = append(results, result)
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return results, nil
}
