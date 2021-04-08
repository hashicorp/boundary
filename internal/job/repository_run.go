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

// RunJobs queries the job repository for available work and returns a slice of *Run
// for each job that needs to be run.  If there are not jobs an empty slice will be returned,
// with a nil error.
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

			for rows.Next() {
				run := allocRun()
				err = r.ScanRows(rows, run)
				if err != nil {
					_ = rows.Close()
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job run"))
				}
				runs = append(runs, run)
			}
			_ = rows.Close()

			// Write Run create messages to oplog
			for _, run := range runs {
				if err = upsertOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_CREATE, nil, run); err != nil {
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
	if err := r.reader.LookupById(ctx, run); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("run %q does not exist", runId)))
		}
		return nil, errors.Wrap(err, op)
	}
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
				return errors.New(errors.InvalidJobRunState, op, "job run is already in a final run state")
			}

			// Write Run update to oplog
			err = upsertOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"CompletedCount", "TotalCount"}, run)
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

// CompleteRun updates the Run repository entry for the provided privateId.
// It sets the status to 'completed' and updates the run's EndTime to the current database time.
// CompleteRun also updates the Job repository entry that is associated with this run,
// setting the NextScheduledRun with the provided nextScheduledRun.
//
// Once a run has been persisted with a final run status (completed, failed
// or interrupted), any future calls to CompleteRun will return an error with Code
// errors.InvalidJobRunState.
// All options are ignored.
func (r *Repository) CompleteRun(ctx context.Context, runId string, nextScheduledRun time.Time, _ ...Option) (*Run, error) {
	const op = "job.(Repository).CompleteRun"
	if runId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing run id")
	}
	if nextScheduledRun.IsZero() {
		return nil, errors.New(errors.InvalidParameter, op, "missing next scheduled run")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	run := allocRun()
	run.PrivateId = runId
	if err := r.reader.LookupById(ctx, run); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("run %q does not exist", runId)))
		}
		return nil, errors.Wrap(err, op)
	}
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, completeRunQuery, []interface{}{runId})
			if err != nil {
				return errors.Wrap(err, op)
			}

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					_ = rows.Close()
					return errors.New(errors.MultipleRecords, op, "more than 1 job run would have been updated")
				}
				rowCnt++
				err = r.ScanRows(rows, run)
				if err != nil {
					_ = rows.Close()
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job run"))
				}
			}
			_ = rows.Close()
			if rowCnt == 0 {
				return errors.New(errors.InvalidJobRunState, op, "job run is already in a final run state")
			}

			// Write Run update to oplog
			err = upsertOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"Status"}, run)
			if err != nil {
				return errors.Wrap(err, op)
			}

			job := allocJob()
			job.PrivateId = run.JobId
			rowsAffected, err := w.Exec(ctx, setNextScheduleRunQuery, []interface{}{nextScheduledRun, job.PrivateId})
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed to set next scheduled run time for job: %s", run.JobId)))
			}
			if rowsAffected == 0 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("unable to set next scheduled run time for job: %s", run.JobId))
			}
			if rowsAffected > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 job would have been updated")
			}

			// Write Job update to oplog
			ticket, err := w.GetTicket(job)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			msg := oplog.Message{
				Message:        interface{}(job).(proto.Message),
				TypeName:       job.TableName(),
				OpType:         oplog.OpType_OP_TYPE_UPDATE,
				FieldMaskPaths: []string{"NextScheduledRun"},
			}
			err = w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, job.oplog(oplog.OpType_OP_TYPE_UPDATE), []*oplog.Message{&msg})
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

// FailRun updates the Run repository entry for the provided privateId.
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
	if err := r.reader.LookupById(ctx, run); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("run %q does not exist", runId)))
		}
		return nil, errors.Wrap(err, op)
	}
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
					_ = rows.Close()
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job run"))
				}
			}
			if rowCnt == 0 {
				return errors.New(errors.InvalidJobRunState, op, "job run is already in a final run state")
			}

			// Write Run update to oplog
			err = upsertOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"Status"}, run)
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

// upsertOplog will write oplog msgs for run upserts. The db.Writer needs to be the writer for the current
// transaction that's executing the upsert.
func upsertOplog(ctx context.Context, w db.Writer, oplogWrapper wrapping.Wrapper, opType oplog.OpType, fieldMasks []string, run *Run) error {
	const op = "job.upsertOplog"
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
