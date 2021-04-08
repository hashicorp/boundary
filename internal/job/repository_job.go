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

// CreateJob inserts a job into the repository and returns a new *Job
// containing the job's PrivateId.  The PrivateId is generated and
// assigned by this method.
//
// • name must be provided and is the user-friendly name of the job.
//
// • code must be provided and is used to uniquely distinguish the same
// base job (job with the same name)
//
// • description must be provided and is the user-friendly description of the job.
//
// WithNextRunIn() is the only valid option.  If this option is not
// provided the NextScheduledRun of the job will default to the current database time,
// and be available to run immediately.
func (r *Repository) CreateJob(ctx context.Context, name, code, description string, opt ...Option) (*Job, error) {
	const op = "job.(Repository).CreateJob"
	if name == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing name")
	}
	if code == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing code")
	}
	if description == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing description")
	}

	id, err := newJobId(name, code)
	if err != nil {
		return nil, errors.Wrap(err, op)
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
				id,
				name,
				code,
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

// LookupJob will look up a job in the repository using the privateId. If the job is not
// found, it will return nil, nil.
//
// All options are ignored.
func (r *Repository) LookupJob(ctx context.Context, privateId string, _ ...Option) (*Job, error) {
	const op = "job.(Repository).LookupJob"
	if privateId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing private id")
	}

	j := allocJob()
	j.PrivateId = privateId
	if err := r.reader.LookupById(ctx, j); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	return j, nil
}

// deleteJob deletes the job for the provided id from the repository
// returning a count of the number of records deleted.
//
// All options are ignored.
func (r *Repository) deleteJob(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "job.(Repository).deleteJob"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing private id")
	}
	j := allocJob()
	j.PrivateId = privateId

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Delete(ctx, j, db.WithOplog(oplogWrapper, j.oplog(oplog.OpType_OP_TYPE_DELETE)))
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
