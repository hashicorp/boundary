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

// Create will create a new iam resource in the db repository with an oplog entry
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

// Update will update an iam resource in the db repository with an oplog entry
func (r *Repository) update(ctx context.Context, resource Resource, fieldMaskPaths []string, opt ...Option) (Resource, error) {
	if resource == nil {
		return nil, errors.New("error updating resource that is nil")
	}
	resourceCloner, ok := resource.(Clonable)
	if !ok {
		return nil, errors.New("error resource is not clonable for update")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("error getting metadata for update: %w", err)
	}
	metadata["op-type"] = []string{strconv.Itoa(int(oplog.OpType_OP_TYPE_UPDATE))}

	var returnedResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			returnedResource = resourceCloner.Clone()
			return w.Update(
				ctx,
				returnedResource,
				fieldMaskPaths,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)
	return returnedResource.(Resource), err
}

func (r *Repository) stdMetadata(ctx context.Context, resource Resource) (oplog.Metadata, error) {
	if s, ok := resource.(*Scope); ok {
		if s.Type == OrganizationScope.String() {
			return oplog.Metadata{
				"resource-public-id": []string{resource.GetPublicId()},
				"scope-id":           []string{s.PublicId},
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
