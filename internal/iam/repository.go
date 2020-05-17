package iam

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

var (
	ErrMetadataScopeNotFound = errors.New("scope not found for metadata")
)

// Repository is the iam database repository
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// NewRepository creates a new iam Repository
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

// create will create a new iam resource in the db repository with an oplog entry
func (r *Repository) create(ctx context.Context, resource Resource, opt ...Option) (Resource, error) {
	if resource == nil {
		return nil, errors.New("error creating resource that is nil")
	}
	resourceCloner, ok := resource.(Clonable)
	if !ok {
		return nil, errors.New("error resource is not clonable for create")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("error getting metadata for create: %w", err)
	}
	metadata["op-type"] = []string{strconv.Itoa(int(oplog.OpType_OP_TYPE_CREATE))}

	var returnedResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			returnedResource = resourceCloner.Clone()
			return w.Create(
				ctx,
				returnedResource,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)
	return returnedResource.(Resource), err
}

// update will update an iam resource in the db repository with an oplog entry
func (r *Repository) update(ctx context.Context, resource Resource, fieldMaskPaths []string, opt ...Option) (Resource, int, error) {
	if resource == nil {
		return nil, db.NoRowsAffected, errors.New("error updating resource that is nil")
	}
	resourceCloner, ok := resource.(Clonable)
	if !ok {
		return nil, db.NoRowsAffected, errors.New("error resource is not clonable for update")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("error getting metadata for update: %w", err)
	}
	metadata["op-type"] = []string{strconv.Itoa(int(oplog.OpType_OP_TYPE_UPDATE))}

	var rowsUpdated int
	var returnedResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			returnedResource = resourceCloner.Clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				returnedResource,
				fieldMaskPaths,
				db.WithOplog(r.wrapper, metadata),
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
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("error getting metadata for delete: %w", err)
	}
	metadata["op-type"] = []string{strconv.Itoa(int(oplog.OpType_OP_TYPE_DELETE))}

	var rowsDeleted int
	var deleteResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			deleteResource = resourceCloner.Clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteResource,
				db.WithOplog(r.wrapper, metadata),
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

func (r *Repository) stdMetadata(ctx context.Context, resource Resource) (oplog.Metadata, error) {
	if s, ok := resource.(*Scope); ok {
		if s.Type == "" {
			if err := r.reader.LookupByPublicId(ctx, s); err != nil {
				return nil, ErrMetadataScopeNotFound
			}
		}
		switch s.Type {
		case OrganizationScope.String():
			return oplog.Metadata{
				"resource-public-id": []string{resource.GetPublicId()},
				"scope-id":           []string{s.PublicId},
				"scope-type":         []string{s.Type},
				"resource-type":      []string{resource.ResourceType().String()},
			}, nil
		default:
			return oplog.Metadata{
				"resource-public-id": []string{resource.GetPublicId()},
				"scope-id":           []string{s.ParentId},
				"scope-type":         []string{s.Type},
				"resource-type":      []string{resource.ResourceType().String()},
			}, nil
		}
	}

	scope, err := resource.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("unable to get scope for standard metadata: %w", err)
	}
	if scope == nil {
		return nil, errors.New("scope was nil for standard metadata")
	}
	return oplog.Metadata{
		"resource-public-id": []string{resource.GetPublicId()},
		"scope-id":           []string{scope.PublicId},
		"scope-type":         []string{scope.Type},
		"resource-type":      []string{resource.ResourceType().String()},
	}, nil
}
