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

// Repository defines an interface for the iam repositories (db, file, inmem, etc).
type Repository interface {
	CreateScope(ctx context.Context, scope *Scope, opt ...Option) (*Scope, error)
	UpdateScope(ctx context.Context, scope *Scope, fieldMaskPaths []string, opt ...Option) (*Scope, error)
	LookupScope(ctx context.Context, opt ...Option) (Scope, error)

	create(ctx context.Context, r Resource, opt ...Option) (Resource, error)
	update(ctx context.Context, r Resource, fieldMaskPaths []string, opt ...Option) (Resource, error)
}

// dbRepository is the iam database repository
type dbRepository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// ensure that dbRepository implements the interfaces of: Repository
var _ Repository = (*dbRepository)(nil)

// NewRepository creates a new iam database repository
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if wrapper == nil {
		return nil, errors.New("error creating db repository with nil wrapper")
	}
	return &dbRepository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// Create will create a new iam resource in the db repository with an oplog entry
func (r *dbRepository) create(ctx context.Context, resource Resource, opt ...Option) (Resource, error) {
	if resource == nil {
		return nil, errors.New("error creating resource that is nil")
	}
	resourceCloner, ok := resource.(ClonableResource)
	if !ok {
		return nil, errors.New("error resource is not clonable for create")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("error getting metadata for create: %w", err)
	}
	metadata["op-type"] = []string{strconv.Itoa(int(oplog.OpType_OP_TYPE_CREATE))}

	var returnedResource Resource
	_, err = r.writer.DoTx(
		ctx,
		20,
		db.ExpBackoff{},
		func(w db.Writer) error {
			returnedResource = resourceCloner.Clone()
			return w.Create(
				context.Background(),
				returnedResource,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)
	return returnedResource, err
}

// Update will update an iam resource in the db repository with an oplog entry
func (r *dbRepository) update(ctx context.Context, resource Resource, fieldMaskPaths []string, opt ...Option) (Resource, error) {
	if resource == nil {
		return nil, errors.New("error updating resource that is nil")
	}
	resourceCloner, ok := resource.(ClonableResource)
	if !ok {
		return nil, errors.New("error resource is not clonable for update")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("error getting metadata for update: %w", err)
	}
	metadata["op-type"] = []string{strconv.Itoa(int(oplog.OpType_OP_TYPE_UPDATE))}

	var returnedResource Resource
	_, err = r.writer.DoTx(
		ctx,
		20,
		db.ExpBackoff{},
		func(w db.Writer) error {
			returnedResource = resourceCloner.Clone()
			return w.Update(
				context.Background(),
				returnedResource,
				fieldMaskPaths,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)
	return returnedResource, err
}

func (r *dbRepository) stdMetadata(ctx context.Context, resource Resource) (oplog.Metadata, error) {
	rType := strconv.Itoa(int(resource.ResourceType()))
	if s, ok := resource.(*Scope); ok {
		if s.Type == OrganizationScope.String() {
			return oplog.Metadata{
				"resource-public-id": []string{resource.GetPublicId()},
				"scope-id":           []string{s.PublicId},
				"scope-type":         []string{s.Type},
				"resource-type":      []string{rType},
			}, nil
		}
	}
	scope, err := resource.GetPrimaryScope(ctx, r.reader)
	if err != nil {
		return nil, err
	}
	if scope == nil {
		return nil, errors.New("error primary scope is nil")
	}
	return oplog.Metadata{
		"resource-public-id": []string{resource.GetPublicId()},
		"scope-id":           []string{scope.PublicId},
		"scope-type":         []string{scope.Type},
		"resource-type":      []string{rType},
	}, nil
}
