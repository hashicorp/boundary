package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
)

// CreateScope will create a scope in the repository and return the written
// scope.  Supported options include: WithPublicId.
func (r *Repository) CreateScope(ctx context.Context, scope *Scope, opt ...Option) (*Scope, error) {
	if scope == nil {
		return nil, fmt.Errorf("create scope: missing scope %w", db.ErrNilParameter)
	}
	if scope.Scope == nil {
		return nil, fmt.Errorf("create scope: missing scope store %w", db.ErrNilParameter)
	}
	if scope.PublicId != "" {
		return nil, fmt.Errorf("create scope: public id not empty: %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	var publicId string
	t := stringToScopeType(scope.Type)
	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, t.Prefix()+"_") {
			return nil, fmt.Errorf("create scope: passed-in public ID %q has wrong prefix for type %q which uses prefix %q", opts.withPublicId, t.String(), t.Prefix())
		}
		publicId = opts.withPublicId
	} else {
		var err error
		publicId, err = newScopeId(t)
		if err != nil {
			return nil, fmt.Errorf("create scope: error generating public id %w for new scope", err)
		}
	}
	s := scope.Clone().(*Scope)
	s.PublicId = publicId
	resource, err := r.create(ctx, s)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create scope: scope %s already exists: %w", s.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create scope: %w for %s", err, s.PublicId)
	}
	return resource.(*Scope), nil
}

// UpdateScope will update a scope in the repository and return the written
// scope.  fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// and everything else is ignored.  If no updatable fields are included in the
// fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateScope(ctx context.Context, scope *Scope, fieldMaskPaths []string, opt ...Option) (*Scope, int, error) {
	if scope == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: missing scope: %w", db.ErrNilParameter)
	}
	if scope.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: missing public id: %w", db.ErrNilParameter)
	}
	if contains(fieldMaskPaths, "ParentId") {
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: you cannot change a scope's parent: %w", db.ErrInvalidFieldMask)
	}
	var dbMask, nullFields []string
	dbMask, nullFields = buildUpdatePaths(
		map[string]interface{}{
			"name":        scope.Name,
			"description": scope.Description,
		},
		fieldMaskPaths,
	)
	// nada to update, so reload scope from db and return it
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: %w", db.ErrEmptyFieldMask)
	}

	resource, rowsUpdated, err := r.update(ctx, scope, dbMask, nullFields)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update scope: %s name %s already exists: %w", scope.PublicId, scope.Name, db.ErrNotUnique)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update scope: failed for public id %s: %w", scope.PublicId, err)
	}
	return resource.(*Scope), rowsUpdated, err
}

// LookupScope will look up a scope in the repository.  If the scope is not
// found, it will return nil, nil.
func (r *Repository) LookupScope(ctx context.Context, withPublicId string, opt ...Option) (*Scope, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup scope: missing public id %w", db.ErrInvalidParameter)
	}
	scope := allocScope()
	scope.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &scope); err != nil {
		if err == db.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup group: failed %w fo %s", err, withPublicId)
	}
	return &scope, nil
}

// DeleteScope will delete a scope from the repository
func (r *Repository) DeleteScope(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete scope: missing public id %w", db.ErrInvalidParameter)
	}
	scope := allocScope()
	scope.PublicId = withPublicId
	rowsDeleted, err := r.delete(ctx, &scope)
	if err != nil {
		if errors.Is(err, ErrMetadataScopeNotFound) {
			return 0, nil
		}
		return db.NoRowsAffected, fmt.Errorf("delete scope: failed %w for %s", err, withPublicId)
	}
	return rowsDeleted, nil
}
