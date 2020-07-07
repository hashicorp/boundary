package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/types/scope"
)

// CreateScope will create a scope in the repository and return the written
// scope.  Supported options include: WithPublicId.
func (r *Repository) CreateScope(ctx context.Context, s *Scope, opt ...Option) (*Scope, error) {
	if s == nil {
		return nil, fmt.Errorf("create scope: missing scope %w", db.ErrNilParameter)
	}
	if s.Scope == nil {
		return nil, fmt.Errorf("create scope: missing scope store %w", db.ErrNilParameter)
	}
	if s.PublicId != "" {
		return nil, fmt.Errorf("create scope: public id not empty: %w", db.ErrInvalidParameter)
	}
	switch s.Type {
	case scope.Unknown.String():
		return nil, fmt.Errorf("create scope: unknown type: %w", db.ErrInvalidParameter)
	case scope.Global.String():
		return nil, fmt.Errorf("create scope: invalid type: %w", db.ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	var publicId string
	t := scope.StringToScopeType(s.Type)
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
	sc := s.Clone().(*Scope)
	sc.PublicId = publicId
	resource, err := r.create(ctx, sc)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create scope: scope %s/%s already exists: %w", sc.PublicId, sc.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create scope: %w for %s", err, sc.PublicId)
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
		return nil, fmt.Errorf("lookup scope: failed %w fo %s", err, withPublicId)
	}
	return &scope, nil
}

// DeleteScope will delete a scope from the repository
func (r *Repository) DeleteScope(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete scope: missing public id %w", db.ErrInvalidParameter)
	}
	if withPublicId == scope.Global.String() {
		return db.NoRowsAffected, fmt.Errorf("delete scope: invalid to delete global scope: %w", db.ErrInvalidParameter)
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

// ListProjects in an organization and supports the WithLimit option.
func (r *Repository) ListProjects(ctx context.Context, withOrganizationId string, opt ...Option) ([]*Scope, error) {
	if withOrganizationId == "" {
		return nil, fmt.Errorf("list projects: missing organization id %w", db.ErrInvalidParameter)
	}
	var projects []*Scope
	err := r.list(ctx, &projects, "parent_id = ? and type = ?", []interface{}{withOrganizationId, scope.Project.String()}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	return projects, nil
}

// ListOrganizations and supports the WithLimit option.
func (r *Repository) ListOrganizations(ctx context.Context, opt ...Option) ([]*Scope, error) {
	var organizations []*Scope
	err := r.list(ctx, &organizations, "parent_id = ? and type = ?", []interface{}{"global", scope.Organization.String()}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	return organizations, nil
}
