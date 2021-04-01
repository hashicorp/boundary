package job

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// FetchWork queries the job repository for available work and returns a JobRun
// of a job that needs to be run, if there are not jobs that need to be run nil, nil
// will be returned.
//
// serverId is required and is the private_id of the server that will run the job.
//
// All options are ignored.
func (r *Repository) FetchWork(ctx context.Context, serverId string, _ ...Option) (*JobRun, error) {
	const op = "job.(Repository).FetchWork"
	if serverId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing server id")
	}

	var run *JobRun
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, fetchWorkQuery, nil)
			if err != nil {
				return errors.Wrap(err, op)
			}

			if !rows.Next() {
				// No jobs need to be run
				_ = rows.Close()
				return nil
			}

			j := allocJob()
			if err := r.ScanRows(rows, j); err != nil {
				return errors.Wrap(err, op)
			}

			// FetchWork only gets a single job, close rows after first read
			_ = rows.Close()

			run, err = NewJobRun(j.PrivateId, serverId)
			if err != nil {
				return errors.Wrap(err, op)
			}

			id, err := newJobRunId()
			if err != nil {
				return errors.Wrap(err, op)
			}
			run.PrivateId = id

			err = w.Create(ctx, run)
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

// CheckpointJobRun updates the repository entry for run.PrivateId with the values
// in run for the fields listed in fieldMaskPaths. It returns a new JobRun
// containing the updated values and a count of the number of records
// updated. run is not changed.
//
// run must contain a valid PrivateId. Only run.TotalCount and run.CompletedCount
// can be updated.
//
// Once a run has been persisted with a final run status (completed, failed or interrupted),
// any future CheckpointJobRun attempts will return an error with Code errors.InvalidJobRunState.
// All options are ignored.
func (r *Repository) CheckpointJobRun(ctx context.Context, run *JobRun, fieldMaskPaths []string, _ ...Option) (*JobRun, int, error) {
	const op = "job.(Repository).CheckpointJobRun"
	if run == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing job run")
	}
	if run.JobRun == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing embedded job run")
	}
	if run.PrivateId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing private id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("CompletedCount", f):
		case strings.EqualFold("TotalCount", f):
		default:
			return nil, db.NoRowsAffected, errors.New(errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = common.BuildUpdatePaths(
		map[string]interface{}{
			"CompletedCount": run.CompletedCount,
			"TotalCount":     run.TotalCount,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "empty field mask")
	}

	var rowsUpdated int
	run = run.clone()
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			var err error
			rowsUpdated, err = w.Update(ctx, run, dbMask, nullFields, db.WithWhere("status = ?", []interface{}{Running}))
			if err != nil {
				return errors.Wrap(err, op)
			}
			if rowsUpdated == 0 {
				return errors.New(errors.InvalidJobRunState, op, "job run is already in a final run state")
			}
			if rowsUpdated > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}

	return run, rowsUpdated, nil
}

// EndJobRun updates the JobRun repository entry for the provided privateId.
// It sets the status and updates the run EndTime to the current database time.
// EndJobRun also updates the Job repository entry that is associated with this run,
// setting the NextScheduledRun with the provided nextScheduledRun.
//
// If other fields in JobRun need to be updated, call CheckpointJobRun before calling
// EndJobRun.  Once a run has been persisted with a final run status (completed, failed
// or interrupted), any future calls to EndJobRun will return an error with Code
// errors.InvalidJobRunState.
// All options are ignored.
func (r *Repository) EndJobRun(ctx context.Context, privateId, status string, nextScheduledRun *timestamp.Timestamp, _ ...Option) error {
	const op = "job.(Repository).EndJobRun"
	if privateId == "" {
		return errors.New(errors.InvalidParameter, op, "missing private id")
	}
	if !isFinalRunStatus(status) {
		return errors.New(errors.InvalidParameter, op, "run status must be a final status (completed, failed or interrupted)")
	}
	if nextScheduledRun == nil || nextScheduledRun.Timestamp == nil {
		return errors.New(errors.InvalidParameter, op, "missing next scheduled run")
	}

	run := allocJobRun()
	run.PrivateId = privateId
	if err := r.reader.LookupById(ctx, run); err != nil {
		if errors.IsNotFoundError(err) {
			return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("job run %q not found", privateId)))
		}
		return errors.Wrap(err, op)
	}

	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			var err error
			rowsUpdated, err := w.Exec(ctx, endJobRunQuery, []interface{}{status, privateId})
			if err != nil {
				return errors.Wrap(err, op)
			}
			if rowsUpdated == 0 {
				return errors.New(errors.InvalidJobRunState, op, "job run is already in a final run state")
			}
			if rowsUpdated > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 job run would have been updated")
			}

			rowsAffected, err := w.Exec(ctx, setNextScheduleRunQuery, []interface{}{nextScheduledRun, run.JobId})
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed to set next scheduled run time for job: %s", run.JobId)))
			}
			if rowsAffected == 0 {
				return errors.New(errors.InvalidSessionState, op, fmt.Sprintf("unable to set next scheduled run time for job: %s", run.JobId))
			}
			if rowsAffected > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 job would have been updated")
			}
			return nil
		},
	)
	if err != nil {
		return errors.Wrap(err, op)
	}

	return nil
}

// LookupJobRun will look up a run in the repository using the privateId. If the run is not
// found, it will return nil, nil.
//
// All options are ignored.
func (r *Repository) LookupJobRun(ctx context.Context, privateId string, _ ...Option) (*JobRun, error) {
	const op = "job.(Repository).LookupJobRun"
	if privateId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing private id")
	}

	run := allocJobRun()
	run.PrivateId = privateId
	if err := r.reader.LookupById(ctx, run); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	return run, nil
}

// deleteJobRun deletes the job for the provided id from the repository
// returning a count of the number of records deleted.
//
// All options are ignored.
func (r *Repository) deleteJobRun(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "job.(Repository).deleteJobRun"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing private id")
	}

	run := allocJobRun()
	run.PrivateId = privateId
	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Delete(ctx, run)
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
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", privateId)))
	}

	return rowsDeleted, nil
}
