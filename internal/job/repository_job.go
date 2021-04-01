package job

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// CreateJob inserts j into the repository and returns a new Job
// containing the job's PrivateId, j is not changed. j must not contain
// a PrivateId as the PrivateId is generated and assigned by this method.
//
// * j.Name must be provided and is the user-friendly name of the job.
//
// * j.Code must be provided and is used to uniquely distinguish the same
// base job (job with the same name)
//
// *j.Description must be provided and is the user-friendly description of the job.
//
// All options are ignored.
func (r *Repository) CreateJob(ctx context.Context, j *Job, _ ...Option) (*Job, error) {
	const op = "job.(Repository).CreateJob"
	if j == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing job")
	}
	if j.Job == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing embedded job")
	}
	if j.Name == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing name")
	}
	if j.Description == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing description")
	}
	if j.NextScheduledRun == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing next scheduled run")
	}
	if j.PrivateId != "" {
		return nil, errors.New(errors.InvalidParameter, op, "private id not empty")
	}

	// Clone job so we do not modify the input
	j = j.clone()
	id, err := newJobId(j.Name, j.Code)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	j.PrivateId = id

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			err := w.Create(ctx, j, db.WithOplog(oplogWrapper, j.oplog(oplog.OpType_OP_TYPE_CREATE)))
			if err != nil {
				return errors.Wrap(err, op)
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("name %s already exists", j.Name)))
		}
		return nil, errors.Wrap(err, op)
	}
	return j, nil
}

// UpdateJob updates the repository entry for j.PrivateId with the values
// in j for the fields listed in fieldMaskPaths. It returns a new Job
// containing the updated values and a count of the number of records
// updated. j is not changed.
//
// j must contain a valid PrivateId. Only j.Description, and
// j.NextScheduledRun can be updated.
//
// All options are ignored.
func (r *Repository) UpdateJob(ctx context.Context, j *Job, fieldMaskPaths []string, _ ...Option) (*Job, int, error) {
	const op = "job.(Repository).UpdateJob"
	if j == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing job")
	}
	if j.Job == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing embedded job")
	}
	if j.PrivateId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing private id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Description", f):
		case strings.EqualFold("NextScheduledRun", f):
		default:
			return nil, db.NoRowsAffected, errors.New(errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = common.BuildUpdatePaths(
		map[string]interface{}{
			"Description":      j.Description,
			"NextScheduledRun": j.NextScheduledRun,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "empty field mask")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	j = j.clone()
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			var err error
			rowsUpdated, err = w.Update(ctx, j, dbMask, nullFields, db.WithOplog(oplogWrapper, j.oplog(oplog.OpType_OP_TYPE_UPDATE)))
			if err != nil {
				return errors.Wrap(err, op)
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

	return j, rowsUpdated, nil
}

// LookupJob will look up a job in the repository. If the job is not
// found, it will return nil, nil.
//
// privateId is required.
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
