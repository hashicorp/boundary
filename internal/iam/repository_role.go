// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-dbw"
)

// CreateRole will create a role in the repository and return the written
// role.  No options are currently supported.
func (r *Repository) CreateRole(ctx context.Context, role *Role, _ ...Option) (*Role, error) {
	const op = "iam.(Repository).CreateRole"
	if role == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role")
	}
	if role.Role == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role store")
	}
	if role.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if role.ScopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	id, err := newRoleId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c := role.Clone().(*Role)
	c.PublicId = id
	resource, err := r.create(ctx, c)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("role %s already exists in scope %s", role.Name, role.ScopeId))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", c.PublicId)))
	}
	return resource.(*Role), nil
}

// UpdateRole will update a role in the repository and return the written role.
// fieldMaskPaths provides field_mask.proto paths for fields that should be
// updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and GrantScopeId are the only
// updatable fields, If no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
func (r *Repository) UpdateRole(ctx context.Context, role *Role, version uint32, fieldMaskPaths []string, _ ...Option) (*Role, []*PrincipalRole, []*RoleGrant, int, error) {
	const op = "iam.(Repository).UpdateRole"
	if role == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role")
	}
	if role.Role == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role store")
	}
	if role.PublicId == "" {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		case strings.EqualFold("grantscopeid", f):
		default:
			return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
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
		return nil, nil, nil, db.NoRowsAffected, errors.E(ctx, errors.WithCode(errors.EmptyFieldMask), errors.WithOp(op))
	}
	var resource Resource
	var rowsUpdated int
	var pr []*PrincipalRole
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
				return errors.Wrap(ctx, err, op)
			}
			repo, err := NewRepository(ctx, read, w, r.kms)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			pr, err = repo.ListPrincipalRoles(ctx, role.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			rg, err = repo.ListRoleGrants(ctx, role.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("role %s already exists in org %s", role.Name, role.ScopeId))
		}
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", role.PublicId)))
	}
	return resource.(*Role), pr, rg, rowsUpdated, nil
}

// LookupRole will look up a role in the repository.  If the role is not
// found, it will return nil, nil.
func (r *Repository) LookupRole(ctx context.Context, withPublicId string, _ ...Option) (*Role, []*PrincipalRole, []*RoleGrant, error) {
	const op = "iam.(Repository).LookupRole"
	if withPublicId == "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	role := allocRole()
	role.PublicId = withPublicId
	var pr []*PrincipalRole
	var rg []*RoleGrant
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
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
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", withPublicId)))
	}
	return &role, pr, rg, nil
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

// ListRoles lists roles in the given scopes and supports the options:
//   - WithLimit
//   - WithStartPageAfterItem
func (r *Repository) ListRoles(ctx context.Context, withScopeIds []string, opt ...Option) ([]*Role, error) {
	const op = "iam.(Repository).ListRoles"
	if len(withScopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}

	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	var inClauses []string
	var args []any
	for i, scopeId := range withScopeIds {
		arg := "scope_id_" + strconv.Itoa(i)
		inClauses = append(inClauses, "@"+arg)
		args = append(args, sql.Named(arg, scopeId))
	}
	inClause := strings.Join(inClauses, ", ")
	whereClause := "scope_id in (" + inClause + ")"

	// Ordering and pagination are tightly coupled.
	// We order by update_time ascending so that new
	// and updated items appear at the end of the pagination.
	// We need to further order by public_id to distinguish items
	// with identical update times.
	withOrder := "update_time asc, public_id asc"
	if opts.withStartPageAfterItem != nil {
		// Now that the order is defined, we can use a simple where
		// clause to only include items updated since the specified
		// start of the page. We use greater than or equal for the update
		// time as there may be items with identical update_times. We
		// then use PublicId as a tiebreaker.
		args = append(args,
			sql.Named("after_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("after_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
		whereClause = "(" + whereClause + ") and (update_time > @after_item_update_time or (update_time = @after_item_update_time and public_id > @after_item_id))"
	}

	var roles []*Role
	err := r.reader.SearchWhere(ctx, &roles, whereClause, args, db.WithLimit(limit), db.WithOrder(withOrder))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return roles, nil
}

// listDeletedRoleIds lists the public IDs of any roles deleted since the timestamp provided.
func (r *Repository) listDeletedRoleIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "iam.(Repository).listDeletedRoleIds"
	var deletedRoles []*deletedRole
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedRoles, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted roles"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var roleIds []string
	for _, role := range deletedRoles {
		roleIds = append(roleIds, role.PublicId)
	}
	return roleIds, transactionTimestamp, nil
}

// estimatedRolesCount returns and estimate of the total number of items in the roles table.
func (r *Repository) estimatedRolesCount(ctx context.Context) (int, error) {
	const op = "iam.(Repository).estimatedRolesCount"
	rows, err := r.reader.Query(ctx, estimateCountRoles, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total roles"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total roles"))
		}
	}
	return count, nil
}
