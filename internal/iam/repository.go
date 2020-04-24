package iam

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// Repository defines an interface for the iam repositories (db, file, inmem, etc).
type Repository interface {
	Create(ctx context.Context, r Resource, opt ...Option) (Resource, error)
	Update(ctx context.Context, r Resource, fieldMaskPaths []string, opt ...Option) (Resource, error)
	LookupById(ctx context.Context, publicId string, r Resource, opt ...Option) error
}

// dbRepository is the iam database repository
type dbRepository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// NewDatabaseRepository creates a new iam database repository
func NewDatabaseRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (Repository, error) {
	return &dbRepository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// Create will create a new iam resource in the db repository with an oplog entry
func (r *dbRepository) Create(ctx context.Context, resource Resource, opt ...Option) (Resource, error) {
	resourceCloner, ok := resource.(ClonableResource)
	if !ok {
		return nil, errors.New("error resource is not clonable for create")
	}
	metadata, err := r.scopeMetaData(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("error getting metadata for create: %w", err)
	}
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
				db.WithOplog(true),
				db.WithWrapper(r.wrapper),
				db.WithMetadata(metadata),
			)
		},
	)
	return returnedResource, err
}

// Update will update an iam resource in the db repository with an oplog entry
func (r *dbRepository) Update(ctx context.Context, resource Resource, fieldMaskPaths []string, opt ...Option) (Resource, error) {
	resourceCloner, ok := resource.(ClonableResource)
	if !ok {
		return nil, errors.New("error resource is not clonable for update")
	}
	metadata, err := r.scopeMetaData(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("error getting metadata for update: %w", err)
	}
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
				db.WithOplog(true),
				db.WithWrapper(r.wrapper),
				db.WithMetadata(metadata),
			)
		},
	)
	return returnedResource, err
}

// LookupById will lookup an iam resource from the repository using its public id
func (r *dbRepository) LookupById(ctx context.Context, publicId string, resource Resource, opt ...Option) error {
	resourceId := reflect.ValueOf(resource).Elem().FieldByName("PublicId")
	if !resourceId.IsValid() {
		return errors.New("error resource doesn't have a public id field")
	}
	resourceId.SetString(publicId)
	return r.reader.LookupByPublicId(ctx, resource)
}

// LookupById will lookup an iam resource from the repository using its friendly name
func (r *dbRepository) LookupByFriendlyName(ctx context.Context, name string, resource Resource, opt ...Option) error {
	resourceName := reflect.ValueOf(resource).Elem().FieldByName("FriendlyName")
	if !resourceName.IsValid() {
		return errors.New("error resource doesn't have a friendly name field")
	}
	resourceName.SetString(name)
	return r.reader.LookupByFriendlyName(ctx, resource)
}
func (r *dbRepository) scopeMetaData(ctx context.Context, resource Resource) (oplog.Metadata, error) {
	scope, err := resource.GetPrimaryScope(ctx, r.reader)
	if err != nil {
		return nil, err
	}
	return oplog.Metadata{
		"scope-id":   []string{scope.PublicId},
		"scope-type": []string{strconv.Itoa(int(scope.Type))},
	}, nil
}
