package job

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
)

// CreateJob inserts j into the repository and returns a new Job
// containing the job's PrivateId, j is not changed. j must not contain
// a PrivateId as the PrivateId is generated and assigned by this method.
//
// j.Name must be provided and is the user-friendly name of the job.
// j.Description must be provided and is the user-friendly description of the job.
// j.Code is optional, if it is provided the combination of name and code must be unique.
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

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			err := w.Create(ctx, j)
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

	var rowsUpdated int
	j = j.clone()
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			var err error
			rowsUpdated, err = w.Update(ctx, j, dbMask, nullFields)
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

// ListJobs returns a slice of Jobs for the name.
// WithLimit is the only option supported.
func (r *Repository) ListJobs(ctx context.Context, name string, opt ...Option) ([]*Job, error) {
	const op = "job.(Repository).ListJobs"
	if name == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing name")
	}
	opts := getOpts(opt...)
	limit := r.limit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var jobs []*Job
	err := r.reader.SearchWhere(ctx, &jobs, "name = ?", []interface{}{name}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return jobs, nil
}

// DeleteJob deletes the job for the provided id from the repository
// returning a count of the number of records deleted.
//
// All options are ignored.
func (r *Repository) DeleteJob(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "job.(Repository).DeleteJob"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing private id")
	}
	j := allocJob()
	j.PrivateId = privateId

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Delete(ctx, j)
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
