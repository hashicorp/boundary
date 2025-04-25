// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
	"slices"
	"strings"
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
	if slices.Contains(grantScopes, globals.GrantScopeDescendants) && slices.Contains(grantScopes, globals.GrantScopeChildren) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "only one of descendants or children grant scope can be specified")
	}
	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id", roleId)))
	}
	if scp.Type == scope.Project.String() {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "grant scope cannot be added to a project role")
	}

	// Find existing grant scopes
	roleGrantScopes, err := listRoleGrantScopes(ctx, r.reader, []string{roleId})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grant scopes"))
	}
	found := map[string]struct{}{}
	for _, rgs := range roleGrantScopes {
		found[rgs.ScopeIdOrSpecial] = struct{}{}
	}

	// Check incoming grant scopes to see if they exist so we don't try to add
	// again and cause an integrity error
	addThisGrantScope := false
	var setSpecialScope string
	addRoleGrantScopes := make([]string, 0, len(grantScopes))
	for _, grantScope := range grantScopes {
		if _, ok := found[grantScope]; ok {
			continue
		}
		if grantScope == globals.GrantScopeThis {
			addThisGrantScope = true
			continue
		}
		if grantScope == globals.GrantScopeDescendants || grantScope == globals.GrantScopeChildren {
			setSpecialScope = grantScope
			continue
		}
		addRoleGrantScopes = append(addRoleGrantScopes, grantScope)
	}

	if !addThisGrantScope && setSpecialScope == "" && len(addRoleGrantScopes) == 0 {
		return []*RoleGrantScope{}, nil
	}

	var retRoleGrantScopes []*RoleGrantScope
	var updatedRole Resource
	updateMask := []string{"Version"}

	globalRoleOrgGrantScopes := make([]*globalRoleIndividualOrgGrantScope, 0, len(addRoleGrantScopes))
	globalRoleProjectGrantScopes := make([]*globalRoleIndividualProjectGrantScope, 0, len(addRoleGrantScopes))
	orgRoleGrantScopes := make([]*orgRoleIndividualGrantScope, 0, len(addRoleGrantScopes))

	switch scp.GetType() {
	case scope.Global.String():
		g := allocGlobalRole()
		g.PublicId = roleId
		// this is safe to do since it'll be overridden by the trigger, but we want to guarantee that version
		// is bumped when the globalRole isn't updated
		g.Version = roleVersion + 1
		if addThisGrantScope {
			g.GrantThisRoleScope = true
			updateMask = append(updateMask, "GrantThisRoleScope")
		}
		if setSpecialScope != "" {
			g.GrantScope = setSpecialScope
			updateMask = append(updateMask, "GrantScope")
		}
		updatedRole = &g
		for _, rgs := range addRoleGrantScopes {
			switch {
			case strings.HasPrefix(rgs, globals.OrgPrefix):
				orgRgs, err := newGlobalRoleIndividualOrgGrantScope(ctx, roleId, rgs)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory global role org grant scope"))
				}
				globalRoleOrgGrantScopes = append(globalRoleOrgGrantScopes, orgRgs)
			case strings.HasPrefix(rgs, globals.ProjectPrefix):
				projGrantScope := globals.GrantScopeIndividual
				if setSpecialScope != "" {
					projGrantScope = setSpecialScope
				}
				projRgs, err := newGlobalRoleIndividualProjectGrantScope(ctx, roleId, rgs, projGrantScope)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory global role org grant scope"))
				}
				globalRoleProjectGrantScopes = append(globalRoleProjectGrantScopes, projRgs)
			default:
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("invalid role grant scopes %s", rgs)))
			}
		}
	case scope.Org.String():
		o := allocOrgRole()
		o.PublicId = roleId
		o.Version = roleVersion + 1
		if addThisGrantScope {
			o.GrantThisRoleScope = true
			updateMask = append(updateMask, "GrantThisRoleScope")
		}
		if setSpecialScope != "" {
			o.GrantScope = setSpecialScope
			updateMask = append(updateMask, "GrantScope")
		}
		for _, rgs := range addRoleGrantScopes {
			projRgs, err := newOrgRoleIndividualGrantScope(ctx, roleId, rgs)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory global role org grant scope"))
			}
			orgRoleGrantScopes = append(orgRoleGrantScopes, projRgs)
		}
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid role scope")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(ctx, updatedRole)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedRole, updateMask, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
			}
			switch updatedRole.(type) {
			case *globalRole:
				u := updatedRole.(*globalRole)
				if addThisGrantScope {
					retRoleGrantScopes = append(retRoleGrantScopes, &RoleGrantScope{
						CreateTime:       u.GrantThisRoleScopeUpdateTime,
						RoleId:           u.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					})
				}
				if setSpecialScope != "" {
					retRoleGrantScopes = append(retRoleGrantScopes, &RoleGrantScope{
						CreateTime:       u.GrantScopeUpdateTime,
						RoleId:           u.PublicId,
						ScopeIdOrSpecial: u.GrantScope,
					})
				}
			case *orgRole:
				o := updatedRole.(*orgRole)
				if addThisGrantScope {
					retRoleGrantScopes = append(retRoleGrantScopes, &RoleGrantScope{
						CreateTime:       o.GrantThisRoleScopeUpdateTime,
						RoleId:           o.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					})
				}
				if setSpecialScope != "" {
					retRoleGrantScopes = append(retRoleGrantScopes, &RoleGrantScope{
						CreateTime:       o.GrantScopeUpdateTime,
						RoleId:           o.PublicId,
						ScopeIdOrSpecial: o.GrantScope,
					})
				}
			}

			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}

			msgs = append(msgs, &roleOplogMsg)
			if len(globalRoleOrgGrantScopes) > 0 {
				roleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(globalRoleOrgGrantScopes))
				if err := w.CreateItems(ctx, globalRoleOrgGrantScopes, db.NewOplogMsgs(&roleGrantScopesOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add individual org grant scopes for global role"))
				}
				for _, gro := range globalRoleOrgGrantScopes {
					retRoleGrantScopes = append(retRoleGrantScopes, gro.roleGrantScope())
				}
			}
			if len(globalRoleProjectGrantScopes) > 0 {
				roleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(globalRoleProjectGrantScopes))
				if err := w.CreateItems(ctx, globalRoleProjectGrantScopes, db.NewOplogMsgs(&roleGrantScopesOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add individual proj grant scopes for global role"))
				}
				for _, grp := range globalRoleProjectGrantScopes {
					retRoleGrantScopes = append(retRoleGrantScopes, grp.roleGrantScope())
				}
			}
			if len(orgRoleGrantScopes) > 0 {
				roleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(orgRoleGrantScopes))
				if err := w.CreateItems(ctx, orgRoleGrantScopes, db.NewOplogMsgs(&roleGrantScopesOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add individual proj grant scopes for global role"))
				}
				for _, grp := range orgRoleGrantScopes {
					retRoleGrantScopes = append(retRoleGrantScopes, grp.roleGrantScope())
				}
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scp.PublicId},
				"scope-type":         []string{scp.Type},
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
	return retRoleGrantScopes, nil
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
	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id", roleId)))
	}
	if scp.Type == scope.Project.String() {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "grant scope cannot be deleted from a project role")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	currentGrantScopes, err := listRoleGrantScopes(ctx, r.reader, []string{roleId})
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to list role grant scopes"))
	}
	currentMap := map[string]struct{}{}
	for _, s := range currentGrantScopes {
		currentMap[s.ScopeIdOrSpecial] = struct{}{}
	}

	removeThis := false
	removeSpecial := false
	scopeToRemove := []string{}
	for _, s := range grantScopes {
		if _, ok := currentMap[s]; !ok {
			// grants doesn't exist so no need to delete
			continue
		}
		if s == globals.GrantScopeThis {
			removeThis = true
			continue
		}
		if s == globals.GrantScopeChildren || s == globals.GrantScopeDescendants {
			removeSpecial = true
			continue
		}
		scopeToRemove = append(scopeToRemove, s)
	}
	// nothing to remove
	if len(scopeToRemove) == 0 && !removeThis && !removeSpecial {
		return db.NoRowsAffected, nil
	}

	updateMask := []string{"Version"}
	var updatedRole Resource
	globalRoleOrgToRemove := make([]*globalRoleIndividualOrgGrantScope, 0, len(grantScopes))
	globalRoleProjToRemove := make([]*globalRoleIndividualProjectGrantScope, 0, len(grantScopes))
	orgRoleProjToRemove := make([]*orgRoleIndividualGrantScope, 0, len(grantScopes))
	var totalRowsDeleted int
	switch scp.GetType() {
	case scope.Global.String():
		g := allocGlobalRole()
		g.PublicId = roleId
		g.Version = roleVersion + 1
		if removeThis {
			updateMask = append(updateMask, "GrantThisRoleScope")
			g.GrantThisRoleScope = false
			totalRowsDeleted += 1
		}
		if removeSpecial {
			updateMask = append(updateMask, "GrantScope")
			g.GrantScope = globals.GrantScopeIndividual
			totalRowsDeleted += 1
		}
		updatedRole = &g
		for _, s := range scopeToRemove {
			switch {
			case strings.HasPrefix(s, globals.OrgPrefix):
				globalRoleOrgToRemove = append(globalRoleOrgToRemove, &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:  roleId,
						ScopeId: s,
					},
				})
			case strings.HasPrefix(s, globals.ProjectPrefix):
				globalRoleProjToRemove = append(globalRoleProjToRemove, &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:  roleId,
						ScopeId: s,
					},
				})
			}
		}
	case scope.Org.String():
		o := allocOrgRole()
		o.PublicId = roleId
		o.Version = roleVersion + 1
		if removeThis {
			updateMask = append(updateMask, "GrantThisRoleScope")
			o.GrantThisRoleScope = false
			totalRowsDeleted += 1
		}
		if removeSpecial {
			updateMask = append(updateMask, "GrantScope")
			o.GrantScope = globals.GrantScopeIndividual
			totalRowsDeleted += 1
		}
		updatedRole = &o
		for _, s := range scopeToRemove {
			orgRoleProjToRemove = append(orgRoleProjToRemove, &orgRoleIndividualGrantScope{
				OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
					RoleId:  roleId,
					ScopeId: s,
				},
			})
		}
	default:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "invalid role type")
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(ctx, updatedRole)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedRole, updateMask, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &roleOplogMsg)
			roleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(globalRoleOrgToRemove)+len(globalRoleProjToRemove)+len(orgRoleProjToRemove))
			if len(globalRoleOrgToRemove) > 0 {
				rowsDeleted, err := w.DeleteItems(ctx, globalRoleOrgToRemove, db.NewOplogMsgs(&roleGrantScopesOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to remove global role individual org grants"))
				}
				totalRowsDeleted += rowsDeleted
			}
			if len(globalRoleProjToRemove) > 0 {
				rowsDeleted, err := w.DeleteItems(ctx, globalRoleProjToRemove, db.NewOplogMsgs(&roleGrantScopesOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to remove global role individual project grants"))
				}
				totalRowsDeleted += rowsDeleted
			}
			if len(orgRoleProjToRemove) > 0 {
				rowsDeleted, err := w.DeleteItems(ctx, orgRoleProjToRemove, db.NewOplogMsgs(&roleGrantScopesOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to remove org role individual project grants"))
				}
				totalRowsDeleted += rowsDeleted
			}

			msgs = append(msgs, roleGrantScopesOplogMsgs...)

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scp.PublicId},
				"scope-type":         []string{scp.Type},
				"resource-public-id": []string{updatedRole.GetPublicId()},
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

	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id", roleId)))
	}
	if scp.Type == scope.Project.String() {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "cannot modify grant scopes of a project scoped role")
	}

	// NOTE: Set calculation can safely take place out of the transaction since
	// we are using roleVersion to ensure that we end up operating on the same
	// set of data from this query to the final set in the transaction function

	// Find existing grant scopes
	roleGrantScopes, err := listRoleGrantScopes(ctx, reader, []string{roleId})
	if err != nil {
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
	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var totalRowsDeleted int
	currentRoleGrantScopes = currentRoleGrantScopes[:0]
	txFunc := func(rdr db.Reader, wtr db.Writer) error {
		msgs := make([]*oplog.Message, 0, 2)
		var updatedRole Resource
		switch scp.GetType() {
		case scope.Global.String():
			g := allocGlobalRole()
			g.PublicId = roleId
			g.Version = roleVersion + 1
			updatedRole = &g
		case scope.Org.String():
			o := allocOrgRole()
			o.PublicId = roleId
			o.Version = roleVersion + 1
			updatedRole = &o
		case scope.Project.String():
			p := allocProjectRole()
			p.PublicId = roleId
			p.Version = roleVersion + 1
			updatedRole = &p
		default:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown scope type %s for scope %s", scp.GetType(), scp.GetPublicId()))
		}

		roleTicket, err := wtr.GetTicket(ctx, updatedRole)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
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
			"scope-id":           []string{scp.PublicId},
			"scope-type":         []string{scp.Type},
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

// listRoleGrantScopes returns the grant scopes for the roleId
func listRoleGrantScopes(ctx context.Context, reader db.Reader, roleIds []string) ([]*RoleGrantScope, error) {
	const op = "iam.(Repository).listRoleGrantScopes"
	if len(roleIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role ids")
	}
	rows, err := reader.Query(ctx, roleGrantsScopeQuery, []any{roleIds})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query role grant scopes"))
	}

	if rows.Err() != nil {
		return nil, errors.Wrap(ctx, rows.Err(), op, errors.WithMsg("role grant scope rows error"))
	}
	var result []*RoleGrantScope
	for rows.Next() {
		if err := reader.ScanRows(ctx, rows, &result); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed scan results from querying role scope for: %s", roleIds)))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unexpected error scanning results from querying role scope for: %s", roleIds)))
	}

	return result, nil
}
