package servers

import (
	"context"
	"errors"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
)

// Repository is the jobs database repository
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new jobs Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper, opt ...Option) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if wrapper == nil {
		return nil, errors.New("error creating db repository with nil wrapper")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the watchtower defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		wrapper:      wrapper,
		defaultLimit: opts.withLimit,
	}, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	return r.reader.SearchWhere(ctx, resources, where, args, db.WithLimit(limit))
}

// create will create a new iam resource in the db repository with an oplog entry
func (r *Repository) create(ctx context.Context, resource Resource, opt ...Option) (Resource, error) {
	if resource == nil {
		return nil, errors.New("error creating resource that is nil")
	}
	resourceCloner, ok := resource.(Clonable)
	if !ok {
		return nil, errors.New("error resource is not clonable for create")
	}

	var returnedResource interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedResource = resourceCloner.Clone()
			return w.Create(
				ctx,
				returnedResource,
			)
		},
	)
	return returnedResource.(Resource), err
}

// update will update an iam resource in the db repository with an oplog entry
func (r *Repository) update(ctx context.Context, resource Resource, fieldMaskPaths []string, setToNullPaths []string, opt ...Option) (Resource, int, error) {
	if resource == nil {
		return nil, db.NoRowsAffected, errors.New("error updating resource that is nil")
	}
	resourceCloner, ok := resource.(Clonable)
	if !ok {
		return nil, db.NoRowsAffected, errors.New("error resource is not clonable for update")
	}

	var dbOpts []db.Option
	opts := getOpts(opt...)
	if opts.withSkipVetForWrite {
		dbOpts = append(dbOpts, db.WithSkipVetForWrite(true))
	}

	var rowsUpdated int
	var returnedResource interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedResource = resourceCloner.Clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				returnedResource,
				fieldMaskPaths,
				setToNullPaths,
				dbOpts...,
			)
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New("error more than 1 resource would have been updated ")
			}
			return err
		},
	)
	return returnedResource.(Resource), rowsUpdated, err
}

// delete will delete an iam resource in the db repository with an oplog entry
func (r *Repository) delete(ctx context.Context, resource Resource, opt ...Option) (int, error) {
	if resource == nil {
		return db.NoRowsAffected, errors.New("error deleting resource that is nil")
	}
	resourceCloner, ok := resource.(Clonable)
	if !ok {
		return db.NoRowsAffected, errors.New("error resource is not clonable for delete")
	}

	var rowsDeleted int
	var deleteResource interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteResource = resourceCloner.Clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteResource,
			)
			if err == nil && rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return errors.New("error more than 1 resource would have been deleted ")
			}
			return err
		},
	)
	return rowsDeleted, err
}
