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
}

// NewRepository creates a new jobs Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if wrapper == nil {
		return nil, errors.New("error creating db repository with nil wrapper")
	}
	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) List(ctx context.Context, serverType string, opt ...Option) error {
	opts := getOpts(opt...)
	var limit int
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	_ = limit
	//return r.reader.SearchWhere(ctx, resources, where, args, db.WithLimit(limit))
	return nil
}

// upsert will upsert
func (r *Repository) Upsert(ctx context.Context, server *Server, opt ...Option) ([]*Server, int, error) {
	/*
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
	*/
	return nil, db.NoRowsAffected, nil
}
