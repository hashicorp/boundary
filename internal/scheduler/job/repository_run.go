package job

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"google.golang.org/protobuf/proto"
)

// RunJobs queries the job repository for jobs that need to be run. It creates new entries
// for each job that needs to be run in the job_run repository, returning a slice of *Run.
// If there are not jobs to run, an empty slice will be returned with a nil error.
//
// • serverId is required and is the private_id of the server that will run the jobs.
//
// The only valid option is WithRunJobsLimit, if not provided RunJobs will run only 1 job.
func (r *Repository) RunJobs(ctx context.Context, serverId string, opt ...Option) ([]*Run, error) {
	const op = "job.(Repository).RunJobs"
	if serverId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing server id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	opts := getOpts(opt...)
	var runs []*Run
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, runJobsQuery, []interface{}{serverId, opts.withRunJobsLimit})
			if err != nil {
				return errors.Wrap(err, op)
			}
			defer rows.Close()

			for rows.Next() {
				run := allocRun()
				err = r.ScanRows(rows, run)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job run"))
				}
				runs = append(runs, run)
			}

			// Write Run create messages to oplog
			for _, run := range runs {
				if err = upsertRunOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_CREATE, nil, run); err != nil {
					return errors.Wrap(err, op)
				}
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return runs, nil
}

// UpdateProgress updates the repository entry's completed and total counts for the provided runId.
//
// Once a run has been persisted with a final run status (completed, failed or interrupted),
// any future UpdateProgress attempts will return an error with Code errors.InvalidJobRunState.
// All options are ignored.
func (r *Repository) UpdateProgress(ctx context.Context, runId string, completed, total int, _ ...Option) (*Run, error) {
	const op = "job.(Repository).UpdateProgress"
	if runId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing run id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	run := allocRun()
	run.PrivateId = runId
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, updateProgressQuery, []interface{}{completed, total, runId})
			if err != nil {
				return errors.Wrap(err, op)
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(errors.MultipleRecords, op, "more than 1 job run would have been updated")
				}
				rowCnt++
				err = r.ScanRows(rows, run)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job run"))
				}
			}
			if rowCnt == 0 {
				// Failed to update run, either it does not exist or was in an invalid state
				if err = r.LookupById(ctx, run); err != nil {
					if errors.IsNotFoundError(err) {
						return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("job run %q does not exist", runId)))
					}
					return errors.Wrap(err, op)
				}

				return errors.New(errors.InvalidJobRunState, op, fmt.Sprintf("job run was in a final run state: %v", run.Status))
			}

			// Write Run update to oplog
			err = upsertRunOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"CompletedCount", "TotalCount"}, run)
			if err != nil {
				return errors.Wrap(err, op)
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	return run, nil
}

// CompleteRun updates the Run repository entry for the provided runId.
// It sets the status to 'completed' and updates the run's EndTime to the current database time.
// CompleteRun also updates the Job repository entry that is associated with this run,
// setting the job's NextScheduledRun to the current database time incremented by the nextRunIn
// parameter.
//
// Once a run has been persisted with a final run status (completed, failed
// or interrupted), any future calls to CompleteRun will return an error with Code
// errors.InvalidJobRunState.
// All options are ignored.
func (r *Repository) CompleteRun(ctx context.Context, runId string, nextRunIn time.Duration, _ ...Option) (*Run, error) {
	const op = "job.(Repository).CompleteRun"
	if runId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing run id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	run := allocRun()
	run.PrivateId = runId
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, completeRunQuery, []interface{}{runId})
			if err != nil {
				return errors.Wrap(err, op)
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(errors.MultipleRecords, op, "more than 1 job run would have been updated")
				}
				rowCnt++
				err = r.ScanRows(rows, run)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job run"))
				}
			}
			if rowCnt == 0 {
				// Failed to update run, either it does not exist or was in an invalid state
				if err = r.LookupById(ctx, run); err != nil {
					if errors.IsNotFoundError(err) {
						return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("job run %q does not exist", runId)))
					}
					return errors.Wrap(err, op)
				}

				return errors.New(errors.InvalidJobRunState, op, fmt.Sprintf("job run was in a final run state: %v", run.Status))
			}

			// Write Run update to oplog
			err = upsertRunOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"Status", "EndTime"}, run)
			if err != nil {
				return errors.Wrap(err, op)
			}

			job := allocJob()
			job.PrivateId = run.JobId
			rows1, err := r.Query(ctx, setNextScheduledRunQuery, []interface{}{int(nextRunIn.Round(time.Second).Seconds()), job.PrivateId})
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed to set next scheduled run time for job: %s", run.JobId)))
			}
			defer rows1.Close()

			rowCnt = 0
			for rows1.Next() {
				if rowCnt > 0 {
					return errors.New(errors.MultipleRecords, op, "more than 1 job would have been updated")
				}
				rowCnt++
				err = r.ScanRows(rows1, job)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job"))
				}
			}

			// Write job update to oplog
			err = upsertJobOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"NextScheduledRun"}, job)
			if err != nil {
				return errors.Wrap(err, op)
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	return run, nil
}

// FailRun updates the Run repository entry for the provided runId.
// It sets the status to 'failed' and updates the run's EndTime to the current database time.
//
// Once a run has been persisted with a final run status (completed, failed
// or interrupted), any future calls to FailRun will return an error with Code
// errors.InvalidJobRunState.
// All options are ignored.
func (r *Repository) FailRun(ctx context.Context, runId string, _ ...Option) (*Run, error) {
	const op = "job.(Repository).FailRun"
	if runId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing run id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	run := allocRun()
	run.PrivateId = runId
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, failRunQuery, []interface{}{runId})
			if err != nil {
				return errors.Wrap(err, op)
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(errors.MultipleRecords, op, "more than 1 job run would have been updated")
				}
				rowCnt++
				err = r.ScanRows(rows, run)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job run"))
				}
			}
			if rowCnt == 0 {
				// Failed to update run, either it does not exist or was in an invalid state
				if err = r.LookupById(ctx, run); err != nil {
					if errors.IsNotFoundError(err) {
						return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("job run %q does not exist", runId)))
					}
					return errors.Wrap(err, op)
				}

				return errors.New(errors.InvalidJobRunState, op, fmt.Sprintf("job run was in a final run state: %v", run.Status))
			}

			// Write Run update to oplog
			err = upsertRunOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"Status", "EndTime"}, run)
			if err != nil {
				return errors.Wrap(err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	return run, nil
}

// InterruptRuns updates the Run repository entries for all job runs that have not been
// updated for the provided interruptThreshold. It sets the status to 'interrupted' and
// updates the run's EndTime to the current database time.
//
// Once a run has been persisted with a final run status (completed, failed
// or interrupted), any future calls to InterruptRuns will return an error with Code
// errors.InvalidJobRunState.
// WithServerId is the only valid option
func (r *Repository) InterruptRuns(ctx context.Context, interruptThreshold time.Duration, opt ...Option) ([]*Run, error) {
	const op = "job.(Repository).InterruptRuns"

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	opts := getOpts(opt...)

	// interruptThreshold is seconds in past so * -1
	args := []interface{}{-1 * int(interruptThreshold.Round(time.Second).Seconds())}
	var whereServerId string
	if opts.withServerId != "" {
		whereServerId = "and server_id = ?"
		args = append(args, opts.withServerId)
	}
	query := fmt.Sprintf(interruptRunsQuery, whereServerId)

	var runs []*Run
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, query, args)
			if err != nil {
				return errors.Wrap(err, op)
			}
			defer rows.Close()

			for rows.Next() {
				run := allocRun()
				err = r.ScanRows(rows, run)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job run"))
				}
				runs = append(runs, run)
			}

			// Write Run update to oplog
			for _, run := range runs {
				if err = upsertRunOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"Status", "EndTime"}, run); err != nil {
					return errors.Wrap(err, op)
				}
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
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
		return nil, errors.New(errors.InvalidParameter, op, "missing run id")
	}

	run := allocRun()
	run.PrivateId = runId
	if err := r.reader.LookupById(ctx, run); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", runId)))
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
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing run id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	run := allocRun()
	run.PrivateId = runId
	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Delete(ctx, run, db.WithOplog(oplogWrapper, run.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err != nil {
				return errors.Wrap(err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", runId)))
	}

	return rowsDeleted, nil
}

// upsertRunOplog will write oplog msgs for run upserts. The db.Writer needs to be the writer for the current
// transaction that's executing the upsert.
func upsertRunOplog(ctx context.Context, w db.Writer, oplogWrapper wrapping.Wrapper, opType oplog.OpType, fieldMasks []string, run *Run) error {
	const op = "job.upsertRunOplog"
	ticket, err := w.GetTicket(run)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
	}
	msg := oplog.Message{
		Message:        interface{}(run).(proto.Message),
		TypeName:       run.TableName(),
		OpType:         opType,
		FieldMaskPaths: fieldMasks,
	}
	err = w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, run.oplog(opType), []*oplog.Message{&msg})
	if err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}
