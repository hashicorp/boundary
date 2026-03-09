// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// RunJobs queries the job repository for jobs that need to be run. It creates new entries
// for each job that needs to be run in the job_run repository, returning a slice of *Run.
// If there are not jobs to run, an empty slice will be returned with a nil error.
//
// • serverId is required and is the private_id of the server that will run the jobs.
// No options are supported.
func (r *Repository) RunJobs(ctx context.Context, serverId string, _ ...Option) ([]*Run, error) {
	const op = "job.(Repository).RunJobs"
	if serverId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing server id")
	}

	var runs []*Run
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, runJobsQuery, []any{serverId})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			for rows.Next() {
				run := allocRun()
				err = r.ScanRows(ctx, rows, run)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for job run"))
				}
				runs = append(runs, run)
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for job run"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return runs, nil
}

// UpdateProgress updates the repository entry's completed and total counts for the provided runId.
//
// Once a run has been persisted with a final run status (failed or interrupted),
// any future UpdateProgress attempts will return an error with Code errors.InvalidJobRunState.
// All options are ignored.
func (r *Repository) UpdateProgress(ctx context.Context, runId string, completed, total, retries int, _ ...Option) (*Run, error) {
	const op = "job.(Repository).UpdateProgress"
	if runId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing run id")
	}

	run := allocRun()
	run.PrivateId = runId
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, updateProgressQuery, []any{completed, total, retries, runId})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 job run would have been updated")
				}
				rowCnt++
				err = r.ScanRows(ctx, rows, run)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for job run"))
				}
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for job run"))
			}
			if rowCnt == 0 {
				// Failed to update run, either it does not exist or was in an invalid state
				if err = r.LookupById(ctx, run); err != nil {
					if errors.IsNotFoundError(err) {
						return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("job run %q does not exist", runId)), errors.WithoutEvent())
					}
					return errors.Wrap(ctx, err, op)
				}

				return errors.New(ctx, errors.InvalidJobRunState, op, fmt.Sprintf("job run was in a final run state: %v", run.Status), errors.WithoutEvent())
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}

	return run, nil
}

// CompleteRun is intended to be called when a job completes successfully. It
// deletes the job_run entry for the provided runId. It also updates the Job
// repository entry that is associated with this run, setting the job's
// NextScheduledRun to the current database time incremented by the nextRunIn
// parameter.
//
// If a run is persisted with a final run status (failed or interrupted), any
// calls to CompleteRun will return an error with Code
// errors.InvalidJobRunState. All options are ignored.
func (r *Repository) CompleteRun(ctx context.Context, runId string, nextRunIn time.Duration, _ ...Option) error {
	const op = "job.(Repository).CompleteRun"
	if runId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing run id")
	}

	run := allocRun()
	run.PrivateId = runId
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, completeRunQuery, []any{runId})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 job run would have been updated")
				}
				rowCnt++
				err = r.ScanRows(ctx, rows, run)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for job run"))
				}
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for job run"))
			}
			if rowCnt == 0 {
				// No rows returned from the query: Either it's already been
				// removed or was in a final state (not 'running').
				if err = r.LookupById(ctx, run); err != nil {
					if errors.IsNotFoundError(err) {
						return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("job run %q does not exist", runId)))
					}
					return errors.Wrap(ctx, err, op)
				}

				return errors.New(ctx, errors.InvalidJobRunState, op, fmt.Sprintf("job run was in a final run state: %v", run.Status), errors.WithoutEvent())
			}

			rows1, err := w.Query(ctx, setNextScheduledRunQuery, []any{int(nextRunIn.Round(time.Second).Seconds()), run.JobPluginId, run.JobName})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to set next scheduled run time for job: %s", run.JobName)))
			}
			defer rows1.Close()

			job := allocJob()
			rowCnt = 0
			for rows1.Next() {
				if rowCnt > 0 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 job would have been updated")
				}
				rowCnt++
				err = r.ScanRows(ctx, rows1, job)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for job"))
				}
			}
			if err := rows1.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for job"))
			}

			return nil
		},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// FailRun updates the Run repository entry for the provided runId.
// It sets the status to 'failed' and updates the run's EndTime to the current database
// time, and sets the completed and total counts.
//
// Once a run has been persisted with a final run status (failed
// or interrupted), any future calls to FailRun will return an error with Code
// errors.InvalidJobRunState.
// All options are ignored.
func (r *Repository) FailRun(ctx context.Context, runId string, completed, total, retries int, _ ...Option) (*Run, error) {
	const op = "job.(Repository).FailRun"
	if runId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing run id")
	}

	run := allocRun()
	run.PrivateId = runId
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			// TODO (lcr 07/2021) this can potentially overwrite completed and total values
			// persisted by the scheduler's monitor jobs loop.
			// Add an on update sql trigger to protect the job_run table, once progress
			// values are used in the critical path.
			rows, err := w.Query(ctx, failRunQuery, []any{completed, total, retries, runId})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 job run would have been updated")
				}
				rowCnt++
				err = r.ScanRows(ctx, rows, run)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for job run"))
				}
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for job run"))
			}
			if rowCnt == 0 {
				// Failed to update run, either it does not exist or was in an invalid state
				if err = r.LookupById(ctx, run); err != nil {
					if errors.IsNotFoundError(err) {
						return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("job run %q does not exist", runId)))
					}
					return errors.Wrap(ctx, err, op)
				}

				return errors.New(ctx, errors.InvalidJobRunState, op, fmt.Sprintf("job run was in a final run state: %v", run.Status), errors.WithoutEvent())
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return run, nil
}

// InterruptRuns updates the Run repository entries for all job runs that have not been
// updated for the provided interruptThreshold. It sets the status to 'interrupted' and
// updates the run's EndTime to the current database time.
//
// Once a run has been persisted with a final run status (failed
// or interrupted), any future calls to InterruptRuns will return an error with Code
// errors.InvalidJobRunState.
// WithControllerId is the only valid option
func (r *Repository) InterruptRuns(ctx context.Context, interruptThreshold time.Duration, opt ...Option) ([]*Run, error) {
	const op = "job.(Repository).InterruptRuns"

	opts := getOpts(opt...)

	// interruptThreshold is seconds in past so * -1
	args := []any{-1 * int(interruptThreshold.Round(time.Second).Seconds())}
	var whereControllerId string
	if opts.withControllerId != "" {
		whereControllerId = "and controller_id = ?"
		args = append(args, opts.withControllerId)
	}
	query := fmt.Sprintf(interruptRunsQuery, whereControllerId)

	var runs []*Run
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, query, args)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			for rows.Next() {
				run := allocRun()
				err = r.ScanRows(ctx, rows, run)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for job run"))
				}
				runs = append(runs, run)
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for job run"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return runs, nil
}

// LookupRun will look up a run in the repository using the runId. If the run is not
// found, it will return nil, nil.
//
// All options are ignored.
func (r *Repository) LookupRun(ctx context.Context, runId string, _ ...Option) (*Run, error) {
	const op = "job.(Repository).LookupRun"
	if runId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing run id")
	}

	run := allocRun()
	run.PrivateId = runId
	if err := r.reader.LookupById(ctx, run); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", runId)))
	}
	return run, nil
}

// deleteRun deletes the job for the provided runId from the repository
// returning a count of the number of records deleted.
//
// All options are ignored.
func (r *Repository) deleteRun(ctx context.Context, runId string, _ ...Option) (int, error) {
	const op = "job.(Repository).deleteRun"
	if runId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing run id")
	}

	run := allocRun()
	run.PrivateId = runId
	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Delete(ctx, run)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", runId)))
	}

	return rowsDeleted, nil
}
