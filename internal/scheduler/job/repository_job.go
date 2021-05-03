package job

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"google.golang.org/protobuf/proto"
)

// CreateJob inserts a job into the repository and returns a new *Job.
//
// • name must be provided and is the name of the job.
//
// • description must be provided and is the user-friendly description of the job.
//
// WithNextRunIn is the only valid options.
func (r *Repository) CreateJob(ctx context.Context, name, description string, opt ...Option) (*Job, error) {
	const op = "job.(Repository).CreateJob"
	if name == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing name")
	}
	if description == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing description")
	}

	opts := getOpts(opt...)
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	j := allocJob()
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, createJobQuery, []interface{}{
				defaultPluginId,
				name,
				description,
				int(opts.withNextRunIn.Round(time.Second).Seconds()),
			})
			if err != nil {
				return errors.Wrap(err, op)
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(errors.MultipleRecords, op, "more than 1 job would have been created")
				}
				rowCnt++
				err = r.ScanRows(rows, j)
				if err != nil {
					_ = rows.Close()
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for job"))
				}
			}
			if rowCnt == 0 {
				return errors.New(errors.NotSpecificIntegrity, op, "failed to create new job")
			}

			// Write job create to oplog
			err = upsertJobOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_CREATE, nil, j)
			if err != nil {
				return errors.Wrap(err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("name %s already exists", name)))
		}
		return nil, errors.Wrap(err, op)
	}
	return j, nil
}

// UpdateJobNextRun updates the Job repository entry for the job name
// setting the job's NextScheduledRun to the current database time incremented by
// the nextRunIn parameter.
//
// All options are ignored.
func (r *Repository) UpdateJobNextRun(ctx context.Context, name string, nextRunIn time.Duration, _ ...Option) (*Job, error) {
	const op = "job.(Repository).UpdateJobNextRun"
	if name == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing name")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	j := allocJob()
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, setNextScheduledRunQuery, []interface{}{int(nextRunIn.Round(time.Second).Seconds()), defaultPluginId, name})
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg(
					fmt.Sprintf("failed to set next scheduled run time for job %v", name)))
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(errors.MultipleRecords, op, "more than 1 job would have been updated")
				}
				rowCnt++
				err = r.ScanRows(rows, j)
				if err != nil {
					_ = rows.Close()
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows"))
				}
			}
			if rowCnt == 0 {
				return errors.New(errors.RecordNotFound, op, fmt.Sprintf("job %q does not exist", name))
			}

			// Write job update to oplog
			err = upsertJobOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, []string{"NextScheduledRun"}, j)
			if err != nil {
				return errors.Wrap(err, op)
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return j, nil
}

// LookupJob will look up a job in the repository using the job name. If the job is not
// found, it will return nil, nil.
//
// All options are ignored.
func (r *Repository) LookupJob(ctx context.Context, name string, _ ...Option) (*Job, error) {
	const op = "job.(Repository).LookupJob"
	if name == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing name")
	}

	j := allocJob()
	if err := r.reader.LookupWhere(ctx, j, "name = ?", []interface{}{name}); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %v", name)))
	}
	return j, nil
}

// ListJobs returns a slice of Jobs.
//
// WithName and WithLimit are the only valid options.
func (r *Repository) ListJobs(ctx context.Context, opt ...Option) ([]*Job, error) {
	const op = "job.(Repository).ListJobs"
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var args []interface{}
	var where []string
	if opts.withName != "" {
		where, args = append(where, "name = ?"), append(args, opts.withName)
	}

	var jobs []*Job
	err := r.reader.SearchWhere(ctx, &jobs, strings.Join(where, " and "), args, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return jobs, nil
}

// deleteJob deletes the job for the provided job name from the repository
// returning a count of the number of records deleted.
//
// All options are ignored.
func (r *Repository) deleteJob(ctx context.Context, name string, _ ...Option) (int, error) {
	const op = "job.(Repository).deleteJob"
	if name == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing name")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	j := allocJob()
	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Delete(ctx, j,
				db.WithWhere("name = ?", []interface{}{name}),
				db.WithOplog(oplogWrapper, j.oplog(oplog.OpType_OP_TYPE_DELETE)))
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
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("delete failed for %v", name)))
	}

	return rowsDeleted, nil
}

// upsertJobOplog will write oplog msgs for job upserts. The db.Writer needs to be the writer for the current
// transaction that's executing the upsert.
func upsertJobOplog(ctx context.Context, w db.Writer, oplogWrapper wrapping.Wrapper, opType oplog.OpType, fieldMasks []string, job *Job) error {
	const op = "job.upsertJobOplog"
	ticket, err := w.GetTicket(job)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
	}
	msg := oplog.Message{
		Message:        interface{}(job).(proto.Message),
		TypeName:       job.TableName(),
		OpType:         opType,
		FieldMaskPaths: fieldMasks,
	}
	err = w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, job.oplog(opType), []*oplog.Message{&msg})
	if err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}
