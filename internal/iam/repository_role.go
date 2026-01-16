// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-dbw"
)

// CreateRole will create a role in the repository and return the written
// role.  No options are currently supported.
func (r *Repository) CreateRole(ctx context.Context, role *Role, opt ...Option) (*Role, []*PrincipalRole, []*RoleGrant, []*RoleGrantScope, error) {
	const op = "iam.(Repository).CreateRole"

	switch {
	case role == nil:
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing role")
	case role.PublicId != "":
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	case role.ScopeId == "":
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	id, err := newRoleId(ctx)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op)
	}

	var roleToCreate Resource
	switch {
	case strings.HasPrefix(role.GetScopeId(), globals.GlobalPrefix):
		roleToCreate = &globalRole{
			GlobalRole: &store.GlobalRole{
				PublicId:           id,
				ScopeId:            role.ScopeId,
				Name:               role.Name,
				Description:        role.Description,
				GrantThisRoleScope: true,
				GrantScope:         globals.GrantScopeIndividual,
			},
		}
	case strings.HasPrefix(role.GetScopeId(), globals.OrgPrefix):
		roleToCreate = &orgRole{
			OrgRole: &store.OrgRole{
				PublicId:           id,
				ScopeId:            role.ScopeId,
				Name:               role.Name,
				Description:        role.Description,
				GrantThisRoleScope: true,
				GrantScope:         globals.GrantScopeIndividual,
			},
		}
	case strings.HasPrefix(role.GetScopeId(), globals.ProjectPrefix):
		roleToCreate = &projectRole{
			ProjectRole: &store.ProjectRole{
				PublicId:           id,
				ScopeId:            role.ScopeId,
				Name:               role.Name,
				Description:        role.Description,
				GrantThisRoleScope: true,
			},
		}
	default:
		return nil, nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "invalid scope type")
	}

	var createdRole *Role
	var pr []*PrincipalRole
	var rg []*RoleGrant
	var grantScopes []*RoleGrantScope
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, writer db.Writer) error {
			res, err := r.create(ctx, roleToCreate, WithReaderWriter(reader, writer))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("while creating role"))
			}
			// Do a fresh lookup to get all return values
			createdRole, pr, rg, grantScopes, err = r.LookupRole(ctx, res.GetPublicId(), WithReaderWriter(reader, writer))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		})
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, nil, nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("role %s already exists in scope %s", role.Name, role.ScopeId))
		}
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", roleToCreate.GetPublicId())))
	}
	return createdRole, pr, rg, grantScopes, nil
}

// UpdateRole will update a role in the repository and return the written role.
// fieldMaskPaths provides field_mask.proto paths for fields that should be
// updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and GrantScopeId are the only
// updatable fields, If no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
func (r *Repository) UpdateRole(ctx context.Context, role *Role, version uint32, fieldMaskPaths []string, opt ...Option) (*Role, []*PrincipalRole, []*RoleGrant, []*RoleGrantScope, int, error) {
	const op = "iam.(Repository).UpdateRole"
	if role == nil {
		return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role")
	}
	if role.PublicId == "" {
		return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}

	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			"name":        role.Name,
			"description": role.Description,
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
			scopeType, err := getRoleScopeType(ctx, read, role.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			var res Resource
			switch scopeType {
			case scope.Global:
				res = &globalRole{GlobalRole: &store.GlobalRole{
					PublicId:    role.GetPublicId(),
					ScopeId:     role.GetScopeId(),
					Name:        role.GetName(),
					Description: role.GetDescription(),
					Version:     role.GetVersion(),
				}}
			case scope.Org:
				res = &orgRole{OrgRole: &store.OrgRole{
					PublicId:    role.GetPublicId(),
					ScopeId:     role.GetScopeId(),
					Name:        role.GetName(),
					Description: role.GetDescription(),
					Version:     role.GetVersion(),
				}}
			case scope.Project:
				res = &projectRole{ProjectRole: &store.ProjectRole{
					PublicId:    role.GetPublicId(),
					ScopeId:     role.GetScopeId(),
					Name:        role.GetName(),
					Description: role.GetDescription(),
					Version:     role.GetVersion(),
				}}
			case scope.Unknown:
				return errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unknown scope type for role: %s", role.PublicId))
			}

			resource = res // If we don't have dbMask or nullFields, we'll return this
			if len(dbMask) > 0 || len(nullFields) > 0 {
				resource, rowsUpdated, err = r.update(ctx, res, version, dbMask, nullFields, WithReaderWriter(read, w))
				if err != nil {
					return errors.Wrap(ctx, err, op)
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
			return nil, nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("role %s already exists in scope %s", role.Name, role.ScopeId))
		}
		return nil, nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", role.PublicId)))
	}

	return resource.(*Role), pr, rg, grantScopes, rowsUpdated, nil
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
	var pr []*PrincipalRole
	var rg []*RoleGrant
	var rgs []*RoleGrantScope
	var role *Role

	lookupFunc := func(read db.Reader, w db.Writer) error {
		scopeType, err := getRoleScopeType(ctx, read, withPublicId)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		var res Resource
		switch scopeType {
		case scope.Global:
			gRole := allocGlobalRole()
			gRole.PublicId = withPublicId
			res = &gRole
		case scope.Org:
			oRole := allocOrgRole()
			oRole.PublicId = withPublicId
			res = &oRole
		case scope.Project:
			pRole := allocProjectRole()
			pRole.PublicId = withPublicId
			res = &pRole
		case scope.Unknown:
			return errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unknown scope type for role: %s", role.PublicId))
		}

		if err := read.LookupByPublicId(ctx, res); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		switch res.(type) {
		case *globalRole:
			role = res.(*globalRole).toRole()
		case *orgRole:
			role = res.(*orgRole).toRole()
		case *projectRole:
			role = res.(*projectRole).toRole()
		default:
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unknown role type %T", res)))
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
		rgs, err = listRoleGrantScopes(ctx, read, []string{withPublicId})
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	}

	var err error
	if !util.IsNil(opts.withReader) && !util.IsNil(opts.withWriter) {
		if !opts.withWriter.IsTx(ctx) {
			return nil, nil, nil, nil, errors.New(ctx, errors.Internal, op, "writer is not in transaction")
		}
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
	return role, pr, rg, rgs, nil
}

// DeleteRole will delete a role from the repository.
func (r *Repository) DeleteRole(ctx context.Context, withPublicId string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteRole"
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	scopeType, err := getRoleScopeType(ctx, r.reader, withPublicId)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("cannot find scope for role %s", withPublicId))
	}

	var res Resource
	switch scopeType {
	case scope.Global:
		gRole := allocGlobalRole()
		gRole.PublicId = withPublicId
		res = &gRole
	case scope.Org:
		oRole := allocOrgRole()
		oRole.PublicId = withPublicId
		res = &oRole
	case scope.Project:
		pRole := allocProjectRole()
		pRole.PublicId = withPublicId
		res = &pRole
	default:
		return db.NoRowsAffected, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unknown scope type for role: %s", withPublicId))
	}
	rowsDeleted, err := r.delete(ctx, res)
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
	args = append(args, sql.Named("limit", limit))

	whereClause := "scope_id in @scope_ids"
	args = append(args, sql.Named("scope_ids", withScopeIds))
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}
	return r.queryRoles(ctx, whereClause, args)
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
	args = append(args, sql.Named("limit", limit))
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
	return r.queryRoles(ctx, whereClause, args)
}

func (r *Repository) queryRoles(ctx context.Context, whereClause string, args []any) ([]*Role, time.Time, error) {
	const op = "iam.(Repository).queryRoles"

	query := fmt.Sprintf(listRolesQuery, whereClause)
	var retRoles []*Role
	var retRoleGrantScopes []*RoleGrantScope
	var transactionTimestamp time.Time
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		rows, err := rd.Query(ctx, query, args)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to execute list roles "))
		}
		for rows.Next() {
			var role Role
			if err := rd.ScanRows(ctx, rows, &role); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			retRoles = append(retRoles, &role)
		}
		if rows.Err() != nil {
			return errors.Wrap(ctx, rows.Err(), op)
		}
		if len(retRoles) > 0 {
			roleIds := make([]string, 0, len(retRoles))
			for _, retRole := range retRoles {
				roleIds = append(roleIds, retRole.PublicId)
			}
			retRoleGrantScopes, err = listRoleGrantScopes(ctx, r.reader, roleIds)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
		transactionTimestamp, err = rd.Now(ctx)
		return err
	})
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query roles"))
	}
	roleGrantScopesMap := make(map[string][]*RoleGrantScope)
	for _, rgs := range retRoleGrantScopes {
		roleGrantScopesMap[rgs.RoleId] = append(roleGrantScopesMap[rgs.RoleId], rgs)
	}
	for _, role := range retRoles {
		role.GrantScopes = roleGrantScopesMap[role.PublicId]
	}
	return retRoles, transactionTimestamp, nil
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
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total roles"))
	}
	return count, nil
}

// getRoleScopeType returns scope.Type of the roleId by reading it from the base type iam_role table
// use this to get scope ID to determine which of the role subtype tables to operate on
func getRoleScopeType(ctx context.Context, r db.Reader, roleId string) (scope.Type, error) {
	const op = "iam.getRoleScopeType"
	if roleId == "" {
		return scope.Unknown, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if r == nil {
		return scope.Unknown, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	}
	rows, err := r.Query(ctx, scopeIdFromRoleIdQuery, []any{sql.Named("public_id", roleId)})
	if err != nil {
		return scope.Unknown, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to lookup role scope for :%s", roleId)))
	}
	var scopeIds []string
	for rows.Next() {
		if err := r.ScanRows(ctx, rows, &scopeIds); err != nil {
			return scope.Unknown, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed scan results from querying role scope for :%s", roleId)))
		}
	}
	if err := rows.Err(); err != nil {
		return scope.Unknown, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unexpected error scanning results from querying role scope for :%s", roleId)))
	}
	if len(scopeIds) == 0 {
		return scope.Unknown, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("role %s not found", roleId))
	}
	if len(scopeIds) > 1 {
		return scope.Unknown, errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 row but got: %d", len(scopeIds)))
	}
	scopeId := scopeIds[0]
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		return scope.Global, nil
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		return scope.Org, nil
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		return scope.Project, nil
	default:
		return scope.Unknown, fmt.Errorf("unknown scope type for role %s", roleId)
	}
}

// getRoleScope returns scope of the role
func getRoleScope(ctx context.Context, r db.Reader, roleId string) (*Scope, error) {
	const op = "iam.getRoleScope"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if r == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	}
	rows, err := r.Query(ctx, scopeIdFromRoleIdQuery, []any{sql.Named("public_id", roleId)})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to lookup role scope for :%s", roleId)))
	}
	var scopeIds []string
	for rows.Next() {
		if err := r.ScanRows(ctx, rows, &scopeIds); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed scan results from querying role scope for :%s", roleId)))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unexpected error scanning results from querying role scope for :%s", roleId)))
	}

	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("role %s not found", roleId))
	}
	if len(scopeIds) > 1 {
		return nil, errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 row but got: %d", len(scopeIds)))
	}

	scp := AllocScope()
	scp.PublicId = scopeIds[0]
	err = r.LookupByPublicId(ctx, &scp)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to lookup role scope"))
	}
	return &scp, nil
}
