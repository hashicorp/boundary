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
		return nil, errors.New(ctx, errors.InvalidParameter, op, "grant scope cannot be added to project roles")
	}

	// Find existing grant scopes
	roleGrantScopes, err := listRoleGrantScopes(ctx, r.reader, []string{roleId})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grant scopes"))
	}

	existingGrantScopes := map[string]struct{}{}
	for _, rgs := range roleGrantScopes {
		existingGrantScopes[rgs.ScopeIdOrSpecial] = struct{}{}
	}

	// Check incoming grant scopes to see if they exist so we don't try to add
	// again and cause an integrity error
	addThisGrantScope := false
	var setSpecialScope string
	addRoleGrantScopes := make([]string, 0, len(grantScopes))
	for _, grantScope := range grantScopes {
		if _, ok := existingGrantScopes[grantScope]; ok {
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

	var globalRoleOrgGrantScopes []*globalRoleIndividualOrgGrantScope
	var globalRoleProjectGrantScopes []*globalRoleIndividualProjectGrantScope
	var orgRoleGrantScopes []*orgRoleIndividualGrantScope

	updatedRole, err := allocRoleResourceForGrantScopeChanges(ctx, roleId, scp.GetType())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to allocate role subtype to add role grant scopes"))
	}
	updateMask := []string{"Version"}
	updatedRole.SetVersion(roleVersion + 1)

	if addThisGrantScope {
		updatedRole.SetThisGrantScope(true)
		updateMask = append(updateMask, "GrantThisRoleScope")
	}
	if setSpecialScope != "" {
		updatedRole.SetSpecialScope(setSpecialScope)
		updateMask = append(updateMask, "GrantScope")
	}
	switch scp.GetType() {
	case scope.Global.String():
		projGrantScope := globals.GrantScopeIndividual
		if setSpecialScope != "" {
			projGrantScope = setSpecialScope
		}
		globalRoleOrgGrantScopes, globalRoleProjectGrantScopes, err = individualGlobalRoleGrantScope(ctx, roleId, projGrantScope, addRoleGrantScopes)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to split global roles grant scopes"))
		}
	case scope.Org.String():
		orgRoleGrantScopes, err = individualOrgGrantScope(ctx, roleId, addRoleGrantScopes)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to split org roles grant scopes"))
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
			if addThisGrantScope {
				retRoleGrantScopes = append(retRoleGrantScopes, updatedRole.ThisGrantScope())
			}
			if setSpecialScope != "" {
				retRoleGrantScopes = append(retRoleGrantScopes, updatedRole.SpecialGrantScope())
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
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add individual project grant scopes for global role"))
				}
				for _, grp := range globalRoleProjectGrantScopes {
					retRoleGrantScopes = append(retRoleGrantScopes, grp.roleGrantScope())
				}
			}
			if len(orgRoleGrantScopes) > 0 {
				roleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(orgRoleGrantScopes))
				if err := w.CreateItems(ctx, orgRoleGrantScopes, db.NewOplogMsgs(&roleGrantScopesOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add individual project grant scopes for global role"))
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
	var totalRowsDeleted int
	updatedRole, err := allocRoleResourceForGrantScopeChanges(ctx, roleId, scp.GetType())
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to allocate role resource"))
	}
	updateMask := []string{"Version"}
	updatedRole.SetVersion(roleVersion + 1)

	if removeThis {
		updatedRole.SetThisGrantScope(false)
		updateMask = append(updateMask, "GrantThisRoleScope")
		totalRowsDeleted += 1
	}

	if removeSpecial {
		updatedRole.SetSpecialScope(globals.GrantScopeIndividual)
		updateMask = append(updateMask, "GrantScope")
		totalRowsDeleted += 1
	}
	var globalRoleOrgToRemove []*globalRoleIndividualOrgGrantScope
	var globalRoleProjToRemove []*globalRoleIndividualProjectGrantScope
	var orgRoleProjToRemove []*orgRoleIndividualGrantScope

	switch scp.GetType() {
	case scope.Global.String():
		globalRoleOrgToRemove, globalRoleProjToRemove, err = individualGlobalRoleGrantScope(ctx, roleId, globals.GrantScopeIndividual, scopeToRemove)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to split global roles grant scopes"))
		}
	case scope.Org.String():
		orgRoleProjToRemove, err = individualOrgGrantScope(ctx, roleId, scopeToRemove)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to split org roles grant scopes"))
		}
	default:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "invalid role scope")
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
	originalRoleGrantScopes, err := listRoleGrantScopes(ctx, reader, []string{roleId})
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grant scopes"))
	}
	originalGrantScopeMap := map[string]struct{}{}

	for _, rgs := range originalRoleGrantScopes {
		originalGrantScopeMap[rgs.ScopeIdOrSpecial] = struct{}{}
	}

	toAdd := make(map[string]struct{})
	for _, scopeId := range grantScopes {
		if _, ok := originalGrantScopeMap[scopeId]; ok {
			delete(originalGrantScopeMap, scopeId)
			continue
		}
		toAdd[scopeId] = struct{}{}
	}

	toRemove := make(map[string]struct{})
	for scopeId, _ := range originalGrantScopeMap {
		toRemove[scopeId] = struct{}{}
	}

	totalRowsDeleted := 0
	updateRole, err := allocRoleResourceForGrantScopeChanges(ctx, roleId, scp.GetType())
	if err != nil {
		return nil, 0, errors.Wrap(ctx, err, op, errors.WithMsg("unable to allocate role resource"))
	}
	updateMask := []string{"Version"}
	updateRole.SetVersion(roleVersion + 1)
	_, removeThis := toRemove[globals.GrantScopeThis]
	_, addThis := toAdd[globals.GrantScopeThis]
	switch {
	case addThis:
		updateRole.SetThisGrantScope(true)
		updateMask = append(updateMask, "GrantThisRoleScope")
	case removeThis:
		updateRole.SetThisGrantScope(false)
		updateMask = append(updateMask, "GrantThisRoleScope")
		totalRowsDeleted++
	}

	finalSpecialGrantScope := globals.GrantScopeIndividual
	_, addDescendants := toAdd[globals.GrantScopeDescendants]
	_, addChildren := toAdd[globals.GrantScopeChildren]
	if addDescendants && addChildren {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "only one of ['children', 'descendants'] can be specified: parameter violation: error #100")
	}

	_, removeDescendants := toRemove[globals.GrantScopeDescendants]
	if removeDescendants {
		totalRowsDeleted++
	}
	_, removeChildren := toRemove[globals.GrantScopeChildren]
	if removeChildren {
		totalRowsDeleted++
	}

	switch {
	case addDescendants:
		updateRole.SetSpecialScope(globals.GrantScopeDescendants)
		finalSpecialGrantScope = globals.GrantScopeDescendants
		updateMask = append(updateMask, "GrantScope")
	case addChildren:
		updateRole.SetSpecialScope(globals.GrantScopeChildren)
		finalSpecialGrantScope = globals.GrantScopeChildren
		updateMask = append(updateMask, "GrantScope")
	case removeDescendants || removeChildren:
		updateRole.SetSpecialScope(globals.GrantScopeIndividual)
		updateMask = append(updateMask, "GrantScope")
	}

	var globalRoleIndividualOrgToAdd []*globalRoleIndividualOrgGrantScope
	var globalRoleIndividualProjToAdd []*globalRoleIndividualProjectGrantScope
	var globalRoleIndividualOrgToRemove []*globalRoleIndividualOrgGrantScope
	var globalRoleIndividualProjToRemove []*globalRoleIndividualProjectGrantScope

	var orgRoleIndividualScopeToAdd []*orgRoleIndividualGrantScope
	var orgRoleIndividualScopeToRemove []*orgRoleIndividualGrantScope

	individualScopesToAdd := make([]string, 0, len(toAdd))
	for scopeId, _ := range toAdd {
		if scopeId == globals.GrantScopeThis ||
			scopeId == globals.GrantScopeDescendants ||
			scopeId == globals.GrantScopeChildren {
			continue
		}
		individualScopesToAdd = append(individualScopesToAdd, scopeId)
	}

	individualScopesToRemove := make([]string, 0, len(toRemove))
	for scopeId, _ := range toRemove {
		if scopeId == globals.GrantScopeThis ||
			scopeId == globals.GrantScopeDescendants ||
			scopeId == globals.GrantScopeChildren {
			continue
		}
		individualScopesToRemove = append(individualScopesToRemove, scopeId)
	}

	switch scp.Type {
	case scope.Global.String():
		globalRoleIndividualOrgToAdd, globalRoleIndividualProjToAdd, err = individualGlobalRoleGrantScope(ctx, roleId, finalSpecialGrantScope, individualScopesToAdd)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert global role individual org scopes to scope specific scope object for grant scope addition"))
		}
		globalRoleIndividualOrgToRemove, globalRoleIndividualProjToRemove, err = individualGlobalRoleGrantScope(ctx, roleId, finalSpecialGrantScope, individualScopesToRemove)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert global role individual proj scopes to scope specific scope object for grant scope removal"))
		}

	case scope.Org.String():
		orgRoleIndividualScopeToAdd, err = individualOrgGrantScope(ctx, roleId, individualScopesToAdd)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert org role individual org scopes to scope specific scope object for grant scope addition"))
		}
		orgRoleIndividualScopeToRemove, err = individualOrgGrantScope(ctx, roleId, individualScopesToRemove)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert org role individual proj scopes to scope specific scope object for grant scope removal"))
		}

	default:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid role scope type %s", scp.Type))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var retGrantScopes []*RoleGrantScope
	txFunc := func(rdr db.Reader, wtr db.Writer) error {
		msgs := make([]*oplog.Message, 0, 2)
		roleTicket, err := wtr.GetTicket(ctx, updateRole)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
		}
		if len(globalRoleIndividualOrgToRemove) > 0 {
			roleGrantScopeOplogMsgs := make([]*oplog.Message, 0, len(globalRoleIndividualOrgToRemove))
			rowsDeleted, err := wtr.DeleteItems(ctx, globalRoleIndividualOrgToRemove, db.NewOplogMsgs(&roleGrantScopeOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete role global role individual org grant scope"))
			}
			if rowsDeleted != len(globalRoleIndividualOrgToRemove) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("role grant scope deleted %d did not match request for %d", rowsDeleted, len(globalRoleIndividualOrgToRemove)))
			}
			totalRowsDeleted += rowsDeleted
			msgs = append(msgs, roleGrantScopeOplogMsgs...)

		}
		if len(globalRoleIndividualProjToRemove) > 0 {
			roleGrantScopeOplogMsgs := make([]*oplog.Message, 0, len(globalRoleIndividualProjToRemove))
			rowsDeleted, err := wtr.DeleteItems(ctx, globalRoleIndividualProjToRemove, db.NewOplogMsgs(&roleGrantScopeOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete global role individual project grant scope"))
			}
			if rowsDeleted != len(globalRoleIndividualProjToRemove) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("role grant scope deleted %d did not match request for %d", rowsDeleted, len(globalRoleIndividualProjToRemove)))
			}
			totalRowsDeleted += rowsDeleted
			msgs = append(msgs, roleGrantScopeOplogMsgs...)
		}
		if len(orgRoleIndividualScopeToRemove) > 0 {
			roleGrantScopeOplogMsgs := make([]*oplog.Message, 0, len(orgRoleIndividualScopeToRemove))
			rowsDeleted, err := wtr.DeleteItems(ctx, orgRoleIndividualScopeToRemove, db.NewOplogMsgs(&roleGrantScopeOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete org role individual project grant scope"))
			}
			if rowsDeleted != len(orgRoleIndividualScopeToRemove) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("role grant scope deleted %d did not match request for %d", rowsDeleted, len(orgRoleIndividualScopeToRemove)))
			}
			totalRowsDeleted += rowsDeleted
			msgs = append(msgs, roleGrantScopeOplogMsgs...)
		}

		var roleOplogMsg oplog.Message
		rowsUpdated, err := wtr.Update(ctx, updateRole, updateMask, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role"))
		}
		if rowsUpdated != 1 {
			return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
		}
		msgs = append(msgs, &roleOplogMsg)

		if len(globalRoleIndividualOrgToAdd) > 0 {
			roleGrantScopeOplogMsgs := make([]*oplog.Message, 0, len(globalRoleIndividualOrgToAdd))
			if err := wtr.CreateItems(ctx, globalRoleIndividualOrgToAdd, db.NewOplogMsgs(&roleGrantScopeOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add individual org grant scope for global role during set"))
			}
			msgs = append(msgs, roleGrantScopeOplogMsgs...)
		}
		if len(globalRoleIndividualProjToAdd) > 0 {
			roleGrantScopeOplogMsgs := make([]*oplog.Message, 0, len(globalRoleIndividualProjToAdd))
			if err := wtr.CreateItems(ctx, globalRoleIndividualProjToAdd, db.NewOplogMsgs(&roleGrantScopeOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add individual project grant scope for global role during set"))
			}
			msgs = append(msgs, roleGrantScopeOplogMsgs...)
		}
		if len(orgRoleIndividualScopeToAdd) > 0 {
			roleGrantScopeOplogMsgs := make([]*oplog.Message, 0, len(orgRoleIndividualScopeToAdd))
			if err := wtr.CreateItems(ctx, orgRoleIndividualScopeToAdd, db.NewOplogMsgs(&roleGrantScopeOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add individual project grant scope for org role during set"))
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

		allGrantScopes, err := listRoleGrantScopes(ctx, rdr, []string{roleId})
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current role grant scopes after set"))
		}
		retGrantScopes = allGrantScopes
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
	return retGrantScopes, totalRowsDeleted, nil
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

func individualGlobalRoleGrantScope(ctx context.Context, roleId string, projGrantScope string, grantScopeIds []string) ([]*globalRoleIndividualOrgGrantScope, []*globalRoleIndividualProjectGrantScope, error) {
	const op = "iam.(Repository).individualGlobalRoleGrantScope"
	org := make([]*globalRoleIndividualOrgGrantScope, 0, len(grantScopeIds))
	proj := make([]*globalRoleIndividualProjectGrantScope, 0, len(grantScopeIds))

	for _, rgs := range grantScopeIds {
		switch {
		case strings.HasPrefix(rgs, globals.OrgPrefix):
			org = append(org, &globalRoleIndividualOrgGrantScope{
				GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
					RoleId:     roleId,
					ScopeId:    rgs,
					GrantScope: globals.GrantScopeIndividual,
				},
			})
		case strings.HasPrefix(rgs, globals.ProjectPrefix):
			proj = append(proj, &globalRoleIndividualProjectGrantScope{
				GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
					RoleId:     roleId,
					ScopeId:    rgs,
					GrantScope: projGrantScope,
				},
			})
		default:
			return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "grant scope cannot be added to project roles")
		}
	}
	return org, proj, nil
}

func individualOrgGrantScope(ctx context.Context, roleId string, grantScopeIds []string) ([]*orgRoleIndividualGrantScope, error) {
	const op = "iam.(Repository).individualOrgGrantScope"
	grantScopes := make([]*orgRoleIndividualGrantScope, 0, len(grantScopeIds))
	for _, rgs := range grantScopeIds {
		if !strings.HasPrefix(rgs, globals.ProjectPrefix) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "individually granted scopes must be project for org role")
		}
		grantScopes = append(grantScopes, &orgRoleIndividualGrantScope{
			OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
				RoleId:     roleId,
				ScopeId:    rgs,
				GrantScope: globals.GrantScopeIndividual,
			},
		})
	}
	return grantScopes, nil
}

// allocRoleResourceForGrantScopeChanges allocates an in-memory instance scope-type specific Role with
func allocRoleResourceForGrantScopeChanges(ctx context.Context, roleId string, scopeType string) (roleScopeGranter, error) {
	const op = "iam.(Repository).AllocRoleResourceWithSpecialGrantScope"
	var res roleScopeGranter
	switch scopeType {
	case scope.Global.String():
		g := allocGlobalRole()
		g.PublicId = roleId
		res = &g
	case scope.Org.String():
		o := allocOrgRole()
		o.PublicId = roleId
		res = &o
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid role scope")
	}
	return res, nil
}
