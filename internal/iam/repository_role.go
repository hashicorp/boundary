package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
)

// CreateRole will create a role in the repository and return the written
// role.  No options are currently supported.
func (r *Repository) CreateRole(ctx context.Context, role *Role, opt ...Option) (*Role, error) {
	if role == nil {
		return nil, fmt.Errorf("create role: missing role %w", db.ErrInvalidParameter)
	}
	if role.Role == nil {
		return nil, fmt.Errorf("create role: missing role store %w", db.ErrInvalidParameter)
	}
	if role.PublicId != "" {
		return nil, fmt.Errorf("create role: public id not empty: %w", db.ErrInvalidParameter)
	}
	if role.ScopeId == "" {
		return nil, fmt.Errorf("create role: missing role scope id: %w", db.ErrInvalidParameter)
	}
	id, err := newRoleId()
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}
	c := role.Clone().(*Role)
	c.PublicId = id
	resource, err := r.create(ctx, c)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create role: role %s already exists in scope %s: %w", role.Name, role.ScopeId, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create role: %w for %s", err, c.PublicId)
	}
	return resource.(*Role), err
}

// UpdateRole will update a role in the repository and return the written role.
// fieldMaskPaths provides field_mask.proto paths for fields that should be
// updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and GrantScopeId are the only
// updatable fields, If no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
func (r *Repository) UpdateRole(ctx context.Context, role *Role, version uint32, fieldMaskPaths []string, opt ...Option) (*Role, []PrincipalRole, []*RoleGrant, int, error) {
	if role == nil {
		return nil, nil, nil, db.NoRowsAffected, fmt.Errorf("update role: missing role %w", db.ErrInvalidParameter)
	}
	if role.Role == nil {
		return nil, nil, nil, db.NoRowsAffected, fmt.Errorf("update role: missing role store %w", db.ErrInvalidParameter)
	}
	if role.PublicId == "" {
		return nil, nil, nil, db.NoRowsAffected, fmt.Errorf("update role: missing role public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		case strings.EqualFold("grantscopeid", f):
		default:
			return nil, nil, nil, db.NoRowsAffected, fmt.Errorf("update role: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"name":         role.Name,
			"description":  role.Description,
			"GrantScopeId": role.GrantScopeId,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, nil, db.NoRowsAffected, fmt.Errorf("update role: %w", db.ErrEmptyFieldMask)
	}
	var resource Resource
	var rowsUpdated int
	var pr []PrincipalRole
	var rg []*RoleGrant
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			c := role.Clone().(*Role)
			resource, rowsUpdated, err = r.update(ctx, c, version, dbMask, nullFields)
			if err != nil {
				return err
			}
			repo, err := NewRepository(read, w, r.kms)
			if err != nil {
				return fmt.Errorf("update role: failed creating inner repo: %w for %s", err, role.PublicId)
			}
			pr, err = repo.ListPrincipalRoles(ctx, role.PublicId)
			if err != nil {
				return fmt.Errorf("update role: listing principal roles: %w for %s", err, role.PublicId)
			}
			rg, err = repo.ListRoleGrants(ctx, role.PublicId)
			if err != nil {
				return fmt.Errorf("update role: listing principal roles: %w for %s", err, role.PublicId)
			}
			return nil
		},
	)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, nil, nil, db.NoRowsAffected, fmt.Errorf("update role: role %s already exists in org %s: %w", role.Name, role.ScopeId, db.ErrNotUnique)
		}
		return nil, nil, nil, db.NoRowsAffected, fmt.Errorf("update role: %w for %s", err, role.PublicId)
	}
	return resource.(*Role), pr, rg, rowsUpdated, err
}

// LookupRole will look up a role in the repository.  If the role is not
// found, it will return nil, nil.
func (r *Repository) LookupRole(ctx context.Context, withPublicId string, opt ...Option) (*Role, []PrincipalRole, []*RoleGrant, error) {
	if withPublicId == "" {
		return nil, nil, nil, fmt.Errorf("lookup role: missing public id %w", db.ErrInvalidParameter)
	}
	role := allocRole()
	role.PublicId = withPublicId
	var pr []PrincipalRole
	var rg []*RoleGrant
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupByPublicId(ctx, &role); err != nil {
				return fmt.Errorf("lookup role: failed %w for %s", err, withPublicId)
			}
			repo, err := NewRepository(read, w, r.kms)
			if err != nil {
				return fmt.Errorf("lookup role: failed creating inner repo: %w for %s", err, withPublicId)
			}
			pr, err = repo.ListPrincipalRoles(ctx, withPublicId)
			if err != nil {
				return fmt.Errorf("lookup role: listing principal roles: %w for %s", err, withPublicId)
			}
			rg, err = repo.ListRoleGrants(ctx, withPublicId)
			if err != nil {
				return fmt.Errorf("lookup role: listing principal roles: %w for %s", err, withPublicId)
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, err
	}
	return &role, pr, rg, nil
}

// DeleteRole will delete a role from the repository.
func (r *Repository) DeleteRole(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete role: missing public id %w", db.ErrInvalidParameter)
	}
	role := allocRole()
	role.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &role); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete role: failed %w for %s", err, withPublicId)
	}
	rowsDeleted, err := r.delete(ctx, &role)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete role: failed %w for %s", err, withPublicId)
	}
	return rowsDeleted, nil
}

// ListRoles in a scope and supports WithLimit option.
func (r *Repository) ListRoles(ctx context.Context, withScopeId string, opt ...Option) ([]*Role, error) {
	if withScopeId == "" {
		return nil, fmt.Errorf("list roles: missing scope id %w", db.ErrInvalidParameter)
	}
	var roles []*Role
	err := r.list(ctx, &roles, "scope_id = ?", []interface{}{withScopeId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
}
