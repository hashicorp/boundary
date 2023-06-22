// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-dbw"
)

// CreateRole will create a role in the repository and return the written
// role.  No options are currently supported.
func (r *Repository) CreateRole(ctx context.Context, role *Role, _ ...Option) (*Role, []*PrincipalRole, []*RoleGrant, []*RoleGrantScope, error) {
	const op = "iam.(Repository).CreateRole"
	if role == nil {
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing role")
	}
	if role.Role == nil {
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing role store")
	}
	if role.PublicId != "" {
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if role.ScopeId == "" {
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	id, err := newRoleId(ctx)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	c := role.Clone().(*Role)
	c.PublicId = id

	initialScope := c.GrantScopeId
	if initialScope == "" {
		initialScope = "this"
	}

	var resource Resource
	var pr []*PrincipalRole
	var rg []*RoleGrant
	var grantScopes []*RoleGrantScope
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, writer db.Writer) error {
			resource, err = r.create(ctx, c, WithReaderWriter(reader, writer))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("while creating role"))
			}
			if initialScope != "" {
				_, _, err = r.SetRoleGrantScopes(ctx, id, resource.(*Role).Version, []string{initialScope}, WithReaderWriter(reader, writer))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("while setting grant scopes"))
				}
			}
			// Do a fresh lookup since version may have gone up by 1 or 2 based
			// on grant scope id
			resource, pr, rg, grantScopes, err = r.LookupRole(ctx, resource.(*Role).PublicId, WithReaderWriter(reader, writer))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		})
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, nil, nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("role %s already exists in scope %s", role.Name, role.ScopeId))
		}
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", c.PublicId)))
	}
	// FIXME: This is for ensuring that we properly fix perms calculations
	role = resource.(*Role)
	role.GrantScopeId = ""
	return role, pr, rg, grantScopes, nil
}

// UpdateRole will update a role in the repository and return the written role.
// fieldMaskPaths provides field_mask.proto paths for fields that should be
// updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and GrantScopeId are the only
// updatable fields, If no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
func (r *Repository) UpdateRole(ctx context.Context, role *Role, version uint32, fieldMaskPaths []string, _ ...Option) (*Role, []*PrincipalRole, []*RoleGrant, []*RoleGrantScope, int, error) {
	const op = "iam.(Repository).UpdateRole"
	if role == nil {
		return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role")
	}
	if role.Role == nil {
		return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role store")
	}
	if role.PublicId == "" {
		return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	var wantGrantScopeIdUpdate bool
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		case strings.EqualFold("grantscopeid", f):
			wantGrantScopeIdUpdate = true
		default:
			return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			"name":         role.Name,
			"description":  role.Description,
			"GrantScopeId": role.GrantScopeId,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, nil, nil, db.NoRowsAffected, errors.E(ctx, errors.WithCode(errors.EmptyFieldMask), errors.WithOp(op))
	}
	var resource Resource
	var rowsUpdated int
	var pr []*PrincipalRole
	var rg []*RoleGrant
	var grantScopes []*RoleGrantScope
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			c := role.Clone().(*Role)
			resource, rowsUpdated, err = r.update(ctx, c, version, dbMask, nullFields)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if wantGrantScopeIdUpdate {
				// If the value is empty, they're trying to clear it (e.g. a
				// null field), which is represented by an empty slice in
				// SetRoleGrantScopes
				grantScopeIdToSet := make([]string, 0, 1)
				if c.GrantScopeId != "" {
					grantScopeIdToSet = append(grantScopeIdToSet, c.GrantScopeId)
				}
				_, _, err = r.SetRoleGrantScopes(ctx, role.PublicId, resource.(*Role).Version, grantScopeIdToSet, WithReaderWriter(read, w))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("while setting grant scopes"))
				}
			}
			// Do a fresh lookup since version may have gone up by 1 or 2 based
			// on grant scope id
			resource, pr, rg, grantScopes, err = r.LookupRole(ctx, role.PublicId, WithReaderWriter(read, w))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("role %s already exists in org %s", role.Name, role.ScopeId))
		}
		return nil, nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", role.PublicId)))
	}
	// FIXME: This is for ensuring that we properly fix perms calculations
	role = resource.(*Role)
	role.GrantScopeId = ""
	return role, pr, rg, grantScopes, rowsUpdated, nil
}

// LookupRole will look up a role in the repository.  If the role is not
// found, it will return nil, nil.
//
// Supported options: WithReaderWriter
func (r *Repository) LookupRole(ctx context.Context, withPublicId string, opt ...Option) (*Role, []*PrincipalRole, []*RoleGrant, []*RoleGrantScope, error) {
	const op = "iam.(Repository).LookupRole"
	if withPublicId == "" {
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	opts := getOpts(opt...)
	role := allocRole()
	role.PublicId = withPublicId
	var pr []*PrincipalRole
	var rg []*RoleGrant
	var rgs []*RoleGrantScope

	lookupFunc := func(read db.Reader, w db.Writer) error {
		if err := read.LookupByPublicId(ctx, &role); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		repo, err := NewRepository(ctx, read, w, r.kms)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		pr, err = repo.ListPrincipalRoles(ctx, withPublicId)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		rg, err = repo.ListRoleGrants(ctx, withPublicId)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		rgs, err = repo.ListRoleGrantScopes(ctx, withPublicId)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	}

	var err error
	if opts.withReader != nil && opts.withWriter != nil {
		err = lookupFunc(opts.withReader, opts.withWriter)
	} else {
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			lookupFunc,
		)
	}
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil, nil, nil
		}
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", withPublicId)))
	}
	// FIXME: This is for ensuring that we properly fix perms calculations
	role.GrantScopeId = ""
	return &role, pr, rg, rgs, nil
}

// DeleteRole will delete a role from the repository.
func (r *Repository) DeleteRole(ctx context.Context, withPublicId string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteRole"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	role := allocRole()
	role.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &role); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", withPublicId)))
	}
	rowsDeleted, err := r.delete(ctx, &role)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", withPublicId)))
	}
	return rowsDeleted, nil
}

// ListRoles lists roles in the given scopes and supports WithLimit option.
func (r *Repository) ListRoles(ctx context.Context, withScopeIds []string, opt ...Option) ([]*Role, error) {
	const op = "iam.(Repository).ListRoles"
	if len(withScopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}
	var roles []*Role
	err := r.list(ctx, &roles, "scope_id in (?)", []any{withScopeIds}, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// FIXME: This is for ensuring that we properly fix perms calculations
	for _, role := range roles {
		role.GrantScopeId = ""
	}
	return roles, nil
}
