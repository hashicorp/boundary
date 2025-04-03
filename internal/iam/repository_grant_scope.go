// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/iam/store"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/util"
)

// AddRoleGrantScopes will add role grant scopes associated with the role ID in
// the repository. No options are currently supported. Zero is not a valid value
// for the WithVersion option and will return an error.
func (r *Repository) AddRoleGrantScopes(ctx context.Context, roleId string, roleVersion uint32, grantScopes []string, _ ...Option) ([]*RoleGrantScope, error) {
	const op = "iam.(Repository).AddRoleGrantScopes"

	switch {
	case roleId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	case len(grantScopes) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grant scopes")
	case roleVersion == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	scopeId, err := getRoleScopeId(ctx, r.reader, roleId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id for", roleId)))
	}

	var scope *Scope
	var roleResource Resource
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		roleResource = &globalRole{GlobalRole: &store.GlobalRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s global scope for", roleId)))
		}
		scope = s
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		roleResource = &orgRole{OrgRole: &store.OrgRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s org scope for", roleId)))
		}
		scope = s
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		roleResource = &projectRole{ProjectRole: &store.ProjectRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s project scope for", roleId)))
		}
		scope = s
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid scope type")
	}

	// Find existing grant scopes
	roleGrantScopes := []*RoleGrantScope{}
	if err := r.reader.SearchWhere(ctx, &roleGrantScopes, "role_id = ?", []any{roleId}); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grant scopes"))
	}
	found := map[string]*RoleGrantScope{}
	for _, rgs := range roleGrantScopes {
		found[rgs.ScopeIdOrSpecial] = rgs
	}

	// Check incoming grant scopes to see if they exist so we don't try to add
	// again and cause an integrity error
	addRoleGrantScopes := make([]any, 0, len(grantScopes))
	for _, grantScope := range grantScopes {
		if _, ok := found[grantScope]; !ok {
			addRoleGrantScopes = append(addRoleGrantScopes, grantScope)
		}
	}

	newRoleGrantScopes := make([]*RoleGrantScope, 0, len(addRoleGrantScopes))
	for _, grantScope := range grantScopes {
		roleGrantScope, err := NewRoleGrantScope(ctx, roleResource.GetPublicId(), grantScope)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant scope"))
		}
		newRoleGrantScopes = append(newRoleGrantScopes, roleGrantScope)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(ctx, roleResource)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			// We need to update the role version as that's the aggregate
			var updatedRole Resource
			switch roleResource.(type) {
			case *globalRole:
				updatedRole = &globalRole{GlobalRole: &store.GlobalRole{
					PublicId: roleId,
					Version:  roleVersion + 1,
				}}
			case *orgRole:
				updatedRole = &orgRole{OrgRole: &store.OrgRole{
					PublicId: roleId,
					Version:  roleVersion + 1,
				}}
			case *projectRole:
				updatedRole = &projectRole{ProjectRole: &store.ProjectRole{
					PublicId: roleId,
					Version:  roleVersion + 1,
				}}
			default:
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown role resource type %T", roleResource))
			}
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &roleOplogMsg)
			roleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(newRoleGrantScopes))
			if err := w.CreateItems(ctx, newRoleGrantScopes, db.NewOplogMsgs(&roleGrantScopesOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants"))
			}
			msgs = append(msgs, roleGrantScopesOplogMsgs...)

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, roleTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return newRoleGrantScopes, nil
}

// DeleteRoleGrantScopes will delete role grant scopes associated with the role ID in
// the repository. No options are currently supported. Zero is not a valid value
// for the WithVersion option and will return an error.
func (r *Repository) DeleteRoleGrantScopes(ctx context.Context, roleId string, roleVersion uint32, grantScopes []string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteRoleGrantScopes"

	switch {
	case roleId == "":
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	case len(grantScopes) == 0:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing grant scopes")
	case roleVersion == 0:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	var scope *Scope
	var roleResource Resource
	scopeId, err := getRoleScopeId(ctx, r.reader, roleId)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id for", roleId)))
	}
	role := Role{
		PublicId: roleId,
		ScopeId:  scopeId,
	}
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		roleResource = &globalRole{GlobalRole: &store.GlobalRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s global scope for", roleId)))
		}
		scope = s
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		roleResource = &orgRole{OrgRole: &store.OrgRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s org scope for", roleId)))
		}
		scope = s
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		roleResource = &projectRole{ProjectRole: &store.ProjectRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s project scope for", roleId)))
		}
		scope = s
	default:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "invalid scope type")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, role.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var totalRowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(ctx, &role)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			// We need to update the role version as that's the aggregate
			var updatedRole Resource
			switch roleResource.(type) {
			case *globalRole:
				updatedRole = &globalRole{GlobalRole: &store.GlobalRole{
					PublicId: roleId,
					Version:  roleVersion + 1,
				}}
			case *orgRole:
				updatedRole = &orgRole{OrgRole: &store.OrgRole{
					PublicId: roleId,
					Version:  roleVersion + 1,
				}}
			case *projectRole:
				updatedRole = &projectRole{ProjectRole: &store.ProjectRole{
					PublicId: roleId,
					Version:  roleVersion + 1,
				}}
			default:
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown role resource type %T", roleResource))
			}

			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &roleOplogMsg)

			deleteRoleGrantScopes := make([]*RoleGrantScope, 0, len(grantScopes))
			for _, grantScope := range grantScopes {
				roleGrantScope, err := NewRoleGrantScope(ctx, roleId, grantScope)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant scope"))
				}
				deleteRoleGrantScopes = append(deleteRoleGrantScopes, roleGrantScope)
			}

			if len(deleteRoleGrantScopes) == 0 {
				return nil
			}

			roleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(deleteRoleGrantScopes))
			rowsDeleted, err := w.DeleteItems(ctx, deleteRoleGrantScopes, db.NewOplogMsgs(&roleGrantScopesOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants"))
			}
			totalRowsDeleted = rowsDeleted
			msgs = append(msgs, roleGrantScopesOplogMsgs...)

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{role.PublicId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, roleTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return totalRowsDeleted, nil
}

// SetRoleGrantScopes sets grant scopes on a role (roleId). The role's current
// db version
// must match the roleVersion or an error will be returned. Zero is not a valid
// value for the WithVersion option and will return an error.
func (r *Repository) SetRoleGrantScopes(ctx context.Context, roleId string, roleVersion uint32, grantScopes []string, opt ...Option) ([]*RoleGrantScope, int, error) {
	const op = "iam.(Repository).SetRoleGrantScopes"

	switch {
	case roleId == "":
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	case roleVersion == 0:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	case grantScopes == nil:
		// Explicitly set to zero clears, but treat nil as a mistake
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing grants")
	}

	reader := r.reader
	writer := r.writer
	needFreshReaderWriter := true
	opts := getOpts(opt...)
	if !util.IsNil(opts.withReader) && !util.IsNil(opts.withWriter) {
		reader = opts.withReader
		writer = opts.withWriter
		needFreshReaderWriter = false
	}

	var scope *Scope
	var roleResource Resource
	scopeId, err := getRoleScopeId(ctx, r.reader, roleId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id for", roleId)))
	}
	role := Role{
		PublicId: roleId,
		ScopeId:  scopeId,
	}
	switch {
	case strings.HasPrefix(scopeId, globals.GlobalPrefix):
		roleResource = &globalRole{GlobalRole: &store.GlobalRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s global scope for", roleId)))
		}
		scope = s
	case strings.HasPrefix(scopeId, globals.OrgPrefix):
		roleResource = &orgRole{OrgRole: &store.OrgRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s org scope for", roleId)))
		}
		scope = s
	case strings.HasPrefix(scopeId, globals.ProjectPrefix):
		roleResource = &projectRole{ProjectRole: &store.ProjectRole{
			PublicId: roleId,
			ScopeId:  scopeId,
		}}
		s, err := roleResource.GetScope(ctx, r.reader)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s project scope for", roleId)))
		}
		scope = s
	default:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "invalid scope type")
	}
	// NOTE: Set calculation can safely take place out of the transaction since
	// we are using roleVersion to ensure that we end up operating on the same
	// set of data from this query to the final set in the transaction function

	// Find existing grant scopes
	roleGrantScopes := []*RoleGrantScope{}
	if err := reader.SearchWhere(ctx, &roleGrantScopes, "role_id = ?", []any{roleId}); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grant scopes"))
	}
	found := map[string]*RoleGrantScope{}
	for _, rgs := range roleGrantScopes {
		found[rgs.ScopeIdOrSpecial] = rgs
	}

	// Check incoming grant scopes to see if they exist and if so act appropriately
	currentRoleGrantScopes := make([]*RoleGrantScope, 0, len(grantScopes)+len(found))
	addRoleGrantScopes := make([]*RoleGrantScope, 0, len(grantScopes))
	deleteRoleGrantScopes := make([]*RoleGrantScope, 0, len(grantScopes))
	for _, grantScope := range grantScopes {
		rgs, ok := found[grantScope]
		if ok {
			// If we have an exact match, do nothing, we want to keep
			// it, but remove from found
			currentRoleGrantScopes = append(currentRoleGrantScopes, rgs)
			delete(found, grantScope)
			continue
		}

		// Not found, so add
		rgs, err := NewRoleGrantScope(ctx, roleId, grantScope)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
		}
		addRoleGrantScopes = append(addRoleGrantScopes, rgs)
		currentRoleGrantScopes = append(currentRoleGrantScopes, rgs)
	}

	if len(found) > 0 {
		for _, rgs := range found {
			deleteRoleGrantScopes = append(deleteRoleGrantScopes, rgs)
		}
	}

	if len(addRoleGrantScopes) == 0 && len(deleteRoleGrantScopes) == 0 {
		return currentRoleGrantScopes, db.NoRowsAffected, nil
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var totalRowsDeleted int
	currentRoleGrantScopes = currentRoleGrantScopes[:0]
	txFunc := func(rdr db.Reader, wtr db.Writer) error {
		msgs := make([]*oplog.Message, 0, 2)
		roleTicket, err := wtr.GetTicket(ctx, &role)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
		}
		var updatedRole Resource
		switch roleResource.(type) {
		case *globalRole:
			updatedRole = &globalRole{GlobalRole: &store.GlobalRole{
				PublicId: roleId,
				Version:  roleVersion + 1,
			}}
		case *orgRole:
			updatedRole = &orgRole{OrgRole: &store.OrgRole{
				PublicId: roleId,
				Version:  roleVersion + 1,
			}}
		case *projectRole:
			updatedRole = &projectRole{ProjectRole: &store.ProjectRole{
				PublicId: roleId,
				Version:  roleVersion + 1,
			}}
		default:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown role resource type %T", roleResource))
		}
		var roleOplogMsg oplog.Message
		rowsUpdated, err := wtr.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
		}
		if rowsUpdated != 1 {
			return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
		}
		msgs = append(msgs, &roleOplogMsg)

		// Anything we didn't take out of found needs to be removed. This needs
		// to come before writing in new ones because otherwise we may hit some
		// validation issues.
		if len(deleteRoleGrantScopes) > 0 {
			roleGrantScopeOplogMsgs := make([]*oplog.Message, 0, len(deleteRoleGrantScopes))
			rowsDeleted, err := wtr.DeleteItems(ctx, deleteRoleGrantScopes, db.NewOplogMsgs(&roleGrantScopeOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete role grant scope"))
			}
			if rowsDeleted != len(deleteRoleGrantScopes) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("role grant scope deleted %d did not match request for %d", rowsDeleted, len(deleteRoleGrantScopes)))
			}
			totalRowsDeleted = rowsDeleted
			msgs = append(msgs, roleGrantScopeOplogMsgs...)
		}

		// Write the new ones in
		if len(addRoleGrantScopes) > 0 {
			roleGrantScopeOplogMsgs := make([]*oplog.Message, 0, len(addRoleGrantScopes))
			if err := wtr.CreateItems(ctx, addRoleGrantScopes, db.NewOplogMsgs(&roleGrantScopeOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grant scope during set"))
			}
			msgs = append(msgs, roleGrantScopeOplogMsgs...)
		}

		metadata := oplog.Metadata{
			"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String(), oplog.OpType_OP_TYPE_CREATE.String()},
			"scope-id":           []string{scope.PublicId},
			"scope-type":         []string{scope.Type},
			"resource-public-id": []string{roleId},
		}
		if err := wtr.WriteOplogEntryWith(ctx, oplogWrapper, roleTicket, metadata, msgs); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
		}

		if err := r.list(ctx, &currentRoleGrantScopes, "role_id = ?", []any{roleId}, opt...); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current role grant scopes after set"))
		}

		return nil
	}

	if !needFreshReaderWriter {
		err = txFunc(reader, writer)
	} else {
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			txFunc,
		)
	}
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return currentRoleGrantScopes, totalRowsDeleted, nil
}
