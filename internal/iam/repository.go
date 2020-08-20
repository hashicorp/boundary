package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
)

var (
	ErrMetadataScopeNotFound = errors.New("scope not found for metadata")
)

// Repository is the iam database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new iam Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if kms == nil {
		return nil, errors.New("error creating db repository with nil kms")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
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
	resourceCloner, ok := resource.(Cloneable)
	if !ok {
		return nil, errors.New("error resource is not Cloneable for create")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("error getting metadata for create: %w", err)
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_CREATE.String()}

	scope, err := resource.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("unable to get scope: %w", err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("unable to get oplog wrapper: %w", err)
	}

	var returnedResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedResource = resourceCloner.Clone()
			return w.Create(
				ctx,
				returnedResource,
				db.WithOplog(oplogWrapper, metadata),
			)
		},
	)
	return returnedResource.(Resource), err
}

// update will update an iam resource in the db repository with an oplog entry
func (r *Repository) update(ctx context.Context, resource Resource, version uint32, fieldMaskPaths []string, setToNullPaths []string, opt ...Option) (Resource, int, error) {
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New("resource version cannot be zero during update")
	}
	if resource == nil {
		return nil, db.NoRowsAffected, errors.New("error updating resource that is nil")
	}
	resourceCloner, ok := resource.(Cloneable)
	if !ok {
		return nil, db.NoRowsAffected, errors.New("error resource is not Cloneable for update")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("error getting metadata for update: %w", err)
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_UPDATE.String()}

	dbOpts := []db.Option{
		db.WithVersion(&version),
	}
	opts := getOpts(opt...)
	if opts.withSkipVetForWrite {
		dbOpts = append(dbOpts, db.WithSkipVetForWrite(true))
	}

	var scope *Scope
	switch t := resource.(type) {
	case *Scope:
		scope = t
	default:
		scope, err = resource.GetScope(ctx, r.reader)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("unable to get scope: %w", err)
		}
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("unable to get oplog wrapper: %w", err)
	}
	dbOpts = append(dbOpts, db.WithOplog(oplogWrapper, metadata))

	var rowsUpdated int
	var returnedResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedResource = resourceCloner.Clone()
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
	resourceCloner, ok := resource.(Cloneable)
	if !ok {
		return db.NoRowsAffected, errors.New("error resource is not Cloneable for delete")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("error getting metadata for delete: %w", err)
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_DELETE.String()}

	scope, err := resource.GetScope(ctx, r.reader)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("unable to get scope: %w", err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("unable to get oplog wrapper: %w", err)
	}

	var rowsDeleted int
	var deleteResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteResource = resourceCloner.Clone()
			rowsDeleted, err = w.Delete(
				ctx,
				deleteResource,
				db.WithOplog(oplogWrapper, metadata),
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
		newScope := allocScope()
		newScope.PublicId = s.PublicId
		newScope.Type = s.Type
		if newScope.Type == "" {
			if err := r.reader.LookupByPublicId(ctx, &newScope); err != nil {
				return nil, ErrMetadataScopeNotFound
			}
		}
		switch newScope.Type {
		case scope.Org.String():
			return oplog.Metadata{
				"resource-public-id": []string{resource.GetPublicId()},
				"scope-id":           []string{newScope.PublicId},
				"scope-type":         []string{newScope.Type},
				"resource-type":      []string{resource.ResourceType().String()},
			}, nil
		case scope.Project.String():
			return oplog.Metadata{
				"resource-public-id": []string{resource.GetPublicId()},
				"scope-id":           []string{newScope.ParentId},
				"scope-type":         []string{newScope.Type},
				"resource-type":      []string{resource.ResourceType().String()},
			}, nil
		default:
			return nil, fmt.Errorf("not a supported scope for metadata: %s", s.Type)
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

func contains(ss []string, t string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, t) {
			return true
		}
	}
	return false
}
