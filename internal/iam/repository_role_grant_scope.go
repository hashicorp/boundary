// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
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
	if slices.Contains(grantScopes, globals.GrantScopeDescendants) && slices.Contains(grantScopes, globals.GrantScopeChildren) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "only one of descendants or children grant scope can be specified")
	}
	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id", roleId)))
	}

	// Find existing grant scopes to find duplicate grants
	originalGrantScopes, err := listRoleGrantScopes(ctx, r.reader, []string{roleId})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grant scopes"))
	}

	originalGrantScopeMap := map[string]struct{}{}
	for _, rgs := range originalGrantScopes {
		originalGrantScopeMap[rgs.ScopeIdOrSpecial] = struct{}{}
	}

	// deduplicate and create a map that contains only new grant scope we need to add
	toAdd := make(map[string]struct{})
	for _, scopeId := range grantScopes {
		if _, ok := originalGrantScopeMap[scopeId]; ok {
			delete(originalGrantScopeMap, scopeId)
			continue
		}
		toAdd[scopeId] = struct{}{}
	}

	// no new scope to add so we're returning early
	if len(toAdd) == 0 {
		return []*RoleGrantScope{}, nil
	}

	// Allocate a subtype-specific role and manually bump version to ensure that version gets updated
	// even when only individual grant scopes, which are stored in separate tables, are modified
	updateRole, err := allocRoleScopeGranter(ctx, roleId, scp.GetType())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to allocate role subtype to add role grant scopes"))
	}
	updateRole.setVersion(roleVersion + 1)
	updateMask := []string{"Version"}

	_, addThis := toAdd[globals.GrantScopeThis]
	if addThis {
		updateRole.setGrantThisRoleScope(true)
		updateMask = append(updateMask, "GrantThisRoleScope")
	}

	// finalGrantScope is used to determine 'grant_scope' value for individualGlobalRoleGrantScopes.
	// This only matters if the role is a global role and the grantScopes contains individual project scope, because
	// there are 2 possible values: ['individual', 'children'].
	// If no grant scope is being added, we must use the current value of iam_role_<type>.grant_scope column
	finalGrantScope := globals.GrantScopeIndividual

	_, addChildren := toAdd[globals.GrantScopeChildren]
	_, addDescendants := toAdd[globals.GrantScopeDescendants]

	switch {
	case addDescendants:
		// cannot add 'descendants' when children is already set, only one hierarchical grant scope can be set
		if _, ok := originalGrantScopeMap[globals.GrantScopeChildren]; ok {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "grant scope children already exists, only one of descendants or children grant scope can be specified")
		}
		err = updateRole.setGrantScope(ctx, globals.GrantScopeDescendants)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		updateMask = append(updateMask, "GrantScope")
		finalGrantScope = globals.GrantScopeDescendants
	case addChildren:
		// cannot add 'children' when descendant is already set, only one hierarchical grant scope can be set
		if _, ok := originalGrantScopeMap[globals.GrantScopeDescendants]; ok {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "grant scope descendants already exists, only one of descendants or children grant scope can be specified")
		}
		err = updateRole.setGrantScope(ctx, globals.GrantScopeChildren)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		updateMask = append(updateMask, "GrantScope")
		finalGrantScope = globals.GrantScopeChildren
	default:
		// if no hierarchical grant scope is being added, we need to check if 'children' grant is set
		// to properly set 'grant_scope' on global role's individual project grant scopes value which has
		// two possible values: ['children', 'individual']
		// this is an edge case for global role which can have both children and individual project grant scopes
		if _, ok := originalGrantScopeMap[globals.GrantScopeChildren]; ok {
			finalGrantScope = globals.GrantScopeChildren
		}
	}

	// generate a list of 'individual' scopes that need to be inserted to the database
	// excluding the non-individual grant scopes [this, descendants, children]
	individualScopesToAdd := make([]string, 0, len(toAdd))
	for scopeId := range toAdd {
		switch scopeId {
		case globals.GrantScopeThis, globals.GrantScopeChildren, globals.GrantScopeDescendants:
			continue
		default:
			individualScopesToAdd = append(individualScopesToAdd, scopeId)
		}
	}

	// return early because there's no new scope to add
	if !addDescendants && !addChildren && !addThis && len(individualScopesToAdd) == 0 {
		return []*RoleGrantScope{}, nil
	}

	var retRoleGrantScopes []*RoleGrantScope

	var globalRoleOrgGrantScopes []*globalRoleIndividualOrgGrantScope
	var globalRoleProjectGrantScopes []*globalRoleIndividualProjectGrantScope
	var orgRoleGrantScopes []*orgRoleIndividualGrantScope

	switch scp.GetType() {
	case scope.Global.String():
		globalRoleOrgGrantScopes, globalRoleProjectGrantScopes, err = individualGlobalRoleGrantScope(ctx, roleId, finalGrantScope, individualScopesToAdd)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to split global roles grant scopes"))
		}
	case scope.Org.String():
		orgRoleGrantScopes, err = individualOrgGrantScope(ctx, roleId, individualScopesToAdd)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to split org roles grant scopes"))
		}
	default:
		// granting individual grant scope to roles is only allowed for roles in global and org scopes
		if len(individualScopesToAdd) > 0 {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "individual role grant scope can only be set for global roles or org roles")
		}
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
			roleTicket, err := w.GetTicket(ctx, updateRole)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updateRole, updateMask, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role"))
			}
			if addThis {
				if g, ok := updateRole.grantThisRoleScope(); ok {
					retRoleGrantScopes = append(retRoleGrantScopes, g)
				}
			}
			if addDescendants || addChildren {
				if g, ok := updateRole.grantScope(); ok {
					retRoleGrantScopes = append(retRoleGrantScopes, g)
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
				for _, or := range orgRoleGrantScopes {
					retRoleGrantScopes = append(retRoleGrantScopes, or.roleGrantScope())
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
// This function returns an 'int' representing number of rows deleted.
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

	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	originalGrantScopes, err := listRoleGrantScopes(ctx, r.reader, []string{roleId})
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to list role grant scopes"))
	}
	originalGrantScopeMap := map[string]struct{}{}
	for _, rgs := range originalGrantScopes {
		originalGrantScopeMap[rgs.ScopeIdOrSpecial] = struct{}{}
	}

	toRemove := map[string]struct{}{}
	// finding grants
	for _, s := range grantScopes {
		// grants doesn't exist in the original grant scopes so no need to delete
		if _, ok := originalGrantScopeMap[s]; !ok {
			continue
		}
		toRemove[s] = struct{}{}
	}

	// return early if there's nothing to remove
	if len(toRemove) == 0 {
		return db.NoRowsAffected, nil
	}

	// totalGrantScopeRemoved for special grant scopes ['this', 'descendants', 'children'] must be counted manually,
	// as they are not stored as individual rows. They are stored as columns in the role entry.
	// Individual grant scopes still rely on 'rowsDeleted' number returned from 'DeleteItems' calls, so we calculate
	// a number that simulates the number of scopes removed.
	var totalGrantScopeRemoved int
	updateRole, err := allocRoleScopeGranter(ctx, roleId, scp.GetType())
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to allocate role resource"))
	}
	updateMask := []string{"Version"}
	updateRole.setVersion(roleVersion + 1)

	_, removeThis := toRemove[globals.GrantScopeThis]
	_, removeChildren := toRemove[globals.GrantScopeChildren]
	_, removeDescendants := toRemove[globals.GrantScopeDescendants]

	// handle case where 'this' grant scope is removed
	if removeThis {
		updateRole.setGrantThisRoleScope(false)
		updateMask = append(updateMask, "GrantThisRoleScope")
		// manually bump rows deleted when for deleting 'this' grant scope since this is now
		// a DB row update instead of deleting a row.
		totalGrantScopeRemoved += 1
	}

	// handle case where hierarchical grant scope ['children', 'descendants'] is removed
	// these grants are mutually exclusive so an OR operation is safe here
	if (removeChildren || removeDescendants) && scp.Type != scope.Project.String() {
		updateRole.removeGrantScope()
		updateMask = append(updateMask, "GrantScope")
		// manually bump rows deleted when for deleting hierarchical grant scope since this is now
		// a DB row update instead of deleting a row.
		totalGrantScopeRemoved += 1
	}

	// Generate a list of individual grant scopes that need to be removed from the database
	// excluding non-individual grant scopes [this, descendants, children]
	individualScopesToRemove := make([]string, 0, len(toRemove))
	for scopeId := range toRemove {
		switch scopeId {
		case globals.GrantScopeThis, globals.GrantScopeChildren, globals.GrantScopeDescendants:
			continue
		default:
			individualScopesToRemove = append(individualScopesToRemove, scopeId)
		}
	}

	// split the list of individual scope to remove into type-specific slices
	var globalRoleOrgToRemove []*globalRoleIndividualOrgGrantScope
	var globalRoleProjToRemove []*globalRoleIndividualProjectGrantScope
	var orgRoleProjToRemove []*orgRoleIndividualGrantScope
	switch scp.GetType() {
	case scope.Global.String():
		// projGrantScope can be hardcoded since we're deleting entries, the foreign key check does not apply here
		projGrantScope := globals.GrantScopeIndividual
		globalRoleOrgToRemove, globalRoleProjToRemove, err = individualGlobalRoleGrantScope(ctx, roleId, projGrantScope, individualScopesToRemove)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to split global roles grant scopes"))
		}
	case scope.Org.String():
		orgRoleProjToRemove, err = individualOrgGrantScope(ctx, roleId, individualScopesToRemove)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to split org roles grant scopes"))
		}
	default:
		// granting individual grant scope to roles is only allowed for roles in global and org scopes
		// but deleting individual grant scopes when the grant scope doesn't exist on a role is allowed
		// so we don't return an error here and treat this as a no-op
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(ctx, updateRole)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updateRole, updateMask, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &roleOplogMsg)
			if len(globalRoleOrgToRemove) > 0 {
				globalRoleOrgGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(globalRoleOrgToRemove))
				rowsDeleted, err := w.DeleteItems(ctx, globalRoleOrgToRemove, db.NewOplogMsgs(&globalRoleOrgGrantScopesOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to remove global role individual org grants"))
				}
				totalGrantScopeRemoved += rowsDeleted
				msgs = append(msgs, globalRoleOrgGrantScopesOplogMsgs...)
			}
			if len(globalRoleProjToRemove) > 0 {
				globalRoleProjGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(globalRoleOrgToRemove))
				rowsDeleted, err := w.DeleteItems(ctx, globalRoleProjToRemove, db.NewOplogMsgs(&globalRoleProjGrantScopesOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to remove global role individual project grants"))
				}
				totalGrantScopeRemoved += rowsDeleted
				msgs = append(msgs, globalRoleProjGrantScopesOplogMsgs...)
			}
			if len(orgRoleProjToRemove) > 0 {
				orgRoleGrantScopesOplogMsgs := make([]*oplog.Message, 0, len(orgRoleProjToRemove))
				rowsDeleted, err := w.DeleteItems(ctx, orgRoleProjToRemove, db.NewOplogMsgs(&orgRoleGrantScopesOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to remove org role individual project grants"))
				}
				totalGrantScopeRemoved += rowsDeleted
				msgs = append(msgs, orgRoleGrantScopesOplogMsgs...)
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
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return totalGrantScopeRemoved, nil
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

	// fetch current role scopes
	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id", roleId)))
	}

	// NOTE: Set calculation can safely take place out of the transaction since
	// we are using roleVersion to ensure that we end up operating on the same
	// set of data from this query to the final set in the transaction function

	// Find existing grant scopes
	originalGrantScopes, err := listRoleGrantScopes(ctx, reader, []string{roleId})
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grant scopes"))
	}
	originalGrantScopeMap := map[string]struct{}{}

	for _, rgs := range originalGrantScopes {
		originalGrantScopeMap[rgs.ScopeIdOrSpecial] = struct{}{}
	}

	// finalGrantScopeForIndividualGrantScope is the final value of what 'grant_scope' column of the role will be.
	// this is only important for global roles with individual scopes IDs granted to the role.
	// A foreign key between iam_role_global.grant_scope and iam_role_global_individual_project_grant_scope.grant_scope
	// can either be ['children', 'individual'] which will prevents inserting if the values don't match.
	// Assuming that the value is 'individual' and only set it to 'children' if we're adding a 'children' grant
	// the current value in the database does not matter and will be overridden by this method
	finalGrantScopeForIndividualGrantScope := globals.GrantScopeIndividual
	toAdd := make(map[string]struct{})
	for _, scopeId := range grantScopes {
		if scopeId == globals.GrantScopeChildren {
			// set final grant scope to 'children'. finalGrantScopeForIndividualGrantScope will be used later
			// when constructing entries for individual project grant scope
			// We have to do this before removing the already exist grants in case the role already contains 'children'
			// and the caller attempts to set value to 'children' again
			finalGrantScopeForIndividualGrantScope = scopeId
		}
		if _, ok := originalGrantScopeMap[scopeId]; ok {
			delete(originalGrantScopeMap, scopeId)
			continue
		}
		toAdd[scopeId] = struct{}{}
	}

	toRemove := make(map[string]struct{})
	for scopeId := range originalGrantScopeMap {
		toRemove[scopeId] = struct{}{}
	}

	// return early since there's no grant scope to add or remove
	if len(toAdd) == 0 && len(toRemove) == 0 {
		return []*RoleGrantScope{}, db.NoRowsAffected, nil
	}

	// totalRowsDeleted has to be calculated manually, especially for non-individual grant scopes [this, children, descendants]
	// because those are deleted by updating 'GrantThisRoleScope' and 'GrantScope' column on the role table
	// totalRowsDeleted are kept in place to maintain the existing contract
	totalRowsDeleted := 0
	updateRole, err := allocRoleScopeGranter(ctx, roleId, scp.GetType())
	if err != nil {
		return nil, 0, errors.Wrap(ctx, err, op, errors.WithMsg("unable to allocate role resource"))
	}

	// bump version manually to force version to change when the role entry doesn't
	// version still needs to be bumped when a grant scope is added or removed
	updateMask := []string{"Version"}
	updateRole.setVersion(roleVersion + 1)

	// handle 'this' grant scope - which is now stored in 'GrantThisRoleScope' column
	_, removeThis := toRemove[globals.GrantScopeThis]
	_, addThis := toAdd[globals.GrantScopeThis]
	switch {
	case addThis:
		updateRole.setGrantThisRoleScope(true)
		updateMask = append(updateMask, "GrantThisRoleScope")
	case removeThis:
		updateRole.setGrantThisRoleScope(false)
		updateMask = append(updateMask, "GrantThisRoleScope")
		// manually count row deleted since removing 'this' is done by an update to 'grant_this_role_scope' column
		// on the role record
		totalRowsDeleted++
	}

	// return early if the there's a conflict in grant_scopes we're trying to add
	_, addDescendants := toAdd[globals.GrantScopeDescendants]
	_, addChildren := toAdd[globals.GrantScopeChildren]
	if addDescendants && addChildren {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "only one of ['children', 'descendants'] can be specified")
	}

	_, removeDescendants := toRemove[globals.GrantScopeDescendants]
	_, removeChildren := toRemove[globals.GrantScopeChildren]

	// children and descendants are mutually exclusive so we only need to count row once
	if removeDescendants || removeChildren {
		// manually count row deleted since removing 'descendants' or 'children' is done by an update to 'grant_scope' column
		// on the role record
		totalRowsDeleted++
	}

	// determine the final hierarchical grant scopes stored in `grant_scope` column [`descendants`, `children`]
	// depending on if we're adding or removing grants
	// if descendants or children is being added, set finalGrantScope to the grant-to-be-added
	// to resolve the
	switch {
	case addDescendants:
		err := updateRole.setGrantScope(ctx, globals.GrantScopeDescendants)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		updateMask = append(updateMask, "GrantScope")
	case addChildren:
		err := updateRole.setGrantScope(ctx, globals.GrantScopeChildren)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		updateMask = append(updateMask, "GrantScope")

	case removeDescendants || removeChildren:
		updateRole.removeGrantScope()
		updateMask = append(updateMask, "GrantScope")
	}

	// generate a list of 'individual' scopes that need to be inserted to the database
	// excluding the non-individual grant scopes ['this', 'descendants', 'children']
	individualScopesToAdd := make([]string, 0, len(toAdd))
	for scopeId := range toAdd {
		switch scopeId {
		case globals.GrantScopeThis, globals.GrantScopeChildren, globals.GrantScopeDescendants:
			continue
		default:
			individualScopesToAdd = append(individualScopesToAdd, scopeId)
		}
	}

	// generate a list of 'individual' scopes that need to be removed from the database
	// excluding the non-individual grant scopes ['this', 'descendants', 'children']
	individualScopesToRemove := make([]string, 0, len(toRemove))
	for scopeId := range toRemove {
		switch scopeId {
		case globals.GrantScopeThis, globals.GrantScopeChildren, globals.GrantScopeDescendants:
			continue
		default:
			individualScopesToRemove = append(individualScopesToRemove, scopeId)
		}
	}

	// convert list of individual grant scopes to add and scopes to removed into their respective structs
	// these lists will be passed to CreateItems and DeleteItems to create or remove
	// individual grant scope entries
	var globalRoleIndividualOrgToAdd []*globalRoleIndividualOrgGrantScope
	var globalRoleIndividualProjToAdd []*globalRoleIndividualProjectGrantScope
	var globalRoleIndividualOrgToRemove []*globalRoleIndividualOrgGrantScope
	var globalRoleIndividualProjToRemove []*globalRoleIndividualProjectGrantScope

	var orgRoleIndividualScopeToAdd []*orgRoleIndividualGrantScope
	var orgRoleIndividualScopeToRemove []*orgRoleIndividualGrantScope

	switch scp.Type {
	case scope.Global.String():
		globalRoleIndividualOrgToAdd, globalRoleIndividualProjToAdd, err = individualGlobalRoleGrantScope(ctx, roleId, finalGrantScopeForIndividualGrantScope, individualScopesToAdd)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert global role individual org scopes to scope specific scope object for grant scope addition"))
		}
		globalRoleIndividualOrgToRemove, globalRoleIndividualProjToRemove, err = individualGlobalRoleGrantScope(ctx, roleId, finalGrantScopeForIndividualGrantScope, individualScopesToRemove)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert global role individual proj scopes to scope specific scope object for grant scope removal"))
		}

	case scope.Org.String():
		orgRoleIndividualScopeToAdd, err = individualOrgGrantScope(ctx, roleId, individualScopesToAdd)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert org role individual proj scopes to scope specific scope object for grant scope addition"))
		}
		orgRoleIndividualScopeToRemove, err = individualOrgGrantScope(ctx, roleId, individualScopesToRemove)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("failed to convert org role individual proj scopes to scope specific scope object for grant scope removal"))
		}
	default:
		if len(individualScopesToRemove) > 0 || len(individualScopesToAdd) > 0 {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op,
				fmt.Sprintf("roles in scope type %s does not allow individual role grant scope", scp.Type))
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wra pper"))
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

// individualGlobalRoleGrantScope parses a list individual grant scope IDs to their corresponding struct representation
// projGrantScope (value of iam_role_global.grant_scope) is required because for individually granted project scope
// has a foreign key enforcement that the iam_role_global_individual_project_grant_scope.grant_scope matches iam_role_global.grant_scope)
// which has two possible values: ['individual', 'children']
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

// individualOrgGrantScope converts a list of scope IDs into a slice of *orgRoleIndividualGrantScope
func individualOrgGrantScope(ctx context.Context, roleId string, grantScopeIds []string) ([]*orgRoleIndividualGrantScope, error) {
	const op = "iam.(Repository).individualOrgGrantScope"
	grantScopes := make([]*orgRoleIndividualGrantScope, 0, len(grantScopeIds))
	for _, rgs := range grantScopeIds {
		if !strings.HasPrefix(rgs, globals.ProjectPrefix) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "individually granted scopes must be project for org role")
		}
		grantScopes = append(grantScopes, &orgRoleIndividualGrantScope{
			OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
				RoleId:  roleId,
				ScopeId: rgs,
				// only individual' is allowed here since so we can hard-code this value
				GrantScope: globals.GrantScopeIndividual,
			},
		})
	}
	return grantScopes, nil
}

// allocRoleScopeGranter allocates an in-memory instance scope-type specific Role with
func allocRoleScopeGranter(ctx context.Context, roleId string, scopeType string) (roleGrantScopeUpdater, error) {
	const op = "iam.(Repository).allocRoleScopeGranter"
	var res roleGrantScopeUpdater
	switch scopeType {
	case scope.Global.String():
		g := allocGlobalRole()
		g.PublicId = roleId
		res = &g
	case scope.Org.String():
		o := allocOrgRole()
		o.PublicId = roleId
		res = &o
	case scope.Project.String():
		p := allocProjectRole()
		p.PublicId = roleId
		res = &p
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid role scope")
	}
	return res, nil
}
