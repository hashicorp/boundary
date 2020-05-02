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
	CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error)
	UpdateUser(ctx context.Context, user *User, fieldMaskPaths []string, opt ...Option) (*User, error)
	LookupUser(ctx context.Context, opt ...Option) (User, error)

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

// NewDatabaseRepository creates a new iam database repository
func NewDatabaseRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (Repository, error) {
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

func (r *dbRepository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	resource, err := r.create(context.Background(), user)
	return resource.(*User), err
}
func (r *dbRepository) UpdateUser(ctx context.Context, user *User, fieldMaskPaths []string, opt ...Option) (*User, error) {
	resource, err := r.update(context.Background(), user, fieldMaskPaths)
	return resource.(*User), err
}

func (r *dbRepository) LookupUser(ctx context.Context, opt ...Option) (User, error) {
	opts := GetOpts(opt...)
	withPublicId := opts.withPublicId
	withFriendlyName := opts.withFriendlyName

	user := allocUser()

	if withPublicId != "" {
		user.PublicId = withPublicId
		if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
			return allocUser(), err
		}
		return user, nil
	}
	if withFriendlyName != "" {
		user.PublicId = withFriendlyName
		if err := r.reader.LookupByFriendlyName(ctx, &user); err != nil {
			return allocUser(), err
		}
		return user, nil
	}
	return allocUser(), errors.New("you must loop up users by id or friendly name")
}

func (r *dbRepository) CreateScope(ctx context.Context, scope *Scope, opt ...Option) (*Scope, error) {
	if scope == nil {
		return nil, errors.New("error scope is nil for create")
	}
	resource, err := r.create(context.Background(), scope)
	return resource.(*Scope), err
}
func (r *dbRepository) UpdateScope(ctx context.Context, scope *Scope, fieldMaskPaths []string, opt ...Option) (*Scope, error) {
	if scope == nil {
		return nil, errors.New("error scope is nil for update")
	}
	resource, err := r.update(context.Background(), scope, fieldMaskPaths)
	return resource.(*Scope), err
}
func (r *dbRepository) LookupScope(ctx context.Context, opt ...Option) (Scope, error) {
	opts := GetOpts(opt...)
	withPublicId := opts.withPublicId
	withFriendlyName := opts.withFriendlyName

	scope := allocScope()

	if withPublicId != "" {
		scope.PublicId = withPublicId
		if err := r.reader.LookupByPublicId(ctx, &scope); err != nil {
			return allocScope(), err
		}
		return scope, nil
	}
	if withFriendlyName != "" {
		scope.FriendlyName = withFriendlyName
		if err := r.reader.LookupByFriendlyName(ctx, &scope); err != nil {
			return allocScope(), err
		}
		return scope, nil
	}
	return allocScope(), errors.New("you must loop up scopes by id or friendly name")
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
				db.WithOplog(true),
				db.WithWrapper(r.wrapper),
				db.WithMetadata(metadata),
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
				db.WithOplog(true),
				db.WithWrapper(r.wrapper),
				db.WithMetadata(metadata),
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
