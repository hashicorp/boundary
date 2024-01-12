// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
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

// listRoles lists roles in the given scopes and supports WithLimit option.
func (r *Repository) listRoles(ctx context.Context, withScopeIds []string, opt ...Option) ([]*Role, time.Time, error) {
	const op = "iam.(Repository).listRoles"
	if len(withScopeIds) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)

	limit := r.defaultLimit
	switch {
	case opts.withLimit > 0:
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	case opts.withLimit < 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "limit must be non-negative")
	}

	var args []any
	whereClause := "scope_id in @scope_ids"
	args = append(args, sql.Named("scope_ids", withScopeIds))

	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}
	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("create_time desc, public_id desc")}
	return r.queryRoles(ctx, whereClause, args, dbOpts...)
}

// listRolesRefresh lists roles in the given scopes and supports the
// WithLimit and WithStartPageAfterItem options.
func (r *Repository) listRolesRefresh(ctx context.Context, updatedAfter time.Time, withScopeIds []string, opt ...Option) ([]*Role, time.Time, error) {
	const op = "iam.(Repository).listRolesRefresh"

	switch {
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")

	case len(withScopeIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	opts := getOpts(opt...)

	limit := r.defaultLimit
	switch {
	case opts.withLimit > 0:
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	case opts.withLimit < 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "limit must be non-negative")
	}

	var args []any
	whereClause := "update_time > @updated_after_time and scope_id in @scope_ids"
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
		sql.Named("scope_ids", withScopeIds),
	)
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(update_time, public_id) < (@last_item_update_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("update_time desc, public_id desc")}
	return r.queryRoles(ctx, whereClause, args, dbOpts...)
}

func (r *Repository) queryRoles(ctx context.Context, whereClause string, args []any, opt ...db.Option) ([]*Role, time.Time, error) {
	const op = "iam.(Repository).queryRoles"

	var transactionTimestamp time.Time
	var ret []*Role
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		var inRet []*Role
		if err := rd.SearchWhere(ctx, &inRet, whereClause, args, opt...); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		ret = inRet
		var err error
		transactionTimestamp, err = rd.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return ret, transactionTimestamp, nil
}

// listRoleDeletedIds lists the public IDs of any roles deleted since the timestamp provided.
func (r *Repository) listRoleDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "iam.(Repository).listRoleDeletedIds"
	var deletedResources []*deletedRole
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedResources, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted roles"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var dIds []string
	for _, res := range deletedResources {
		dIds = append(dIds, res.PublicId)
	}
	return dIds, transactionTimestamp, nil
}

// estimatedRoleCount returns an estimate of the total number of items in the iam_role table.
func (r *Repository) estimatedRoleCount(ctx context.Context) (int, error) {
	const op = "iam.(Repository).estimatedRoleCount"
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
