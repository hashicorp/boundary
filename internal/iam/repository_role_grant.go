// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// AddRoleGrant will add role grants associated with the role ID in the
// repository. No options are currently supported. Zero is not a valid value for
// the WithVersion option and will return an error.
func (r *Repository) AddRoleGrants(ctx context.Context, roleId string, roleVersion uint32, grants []string, _ ...Option) ([]*RoleGrant, error) {
	const op = "iam.(Repository).AddRoleGrants"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if len(grants) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants")
	}
	if roleVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	role := allocRole()
	role.PublicId = roleId

	newRoleGrants := make([]any, 0, len(grants))
	for _, grant := range grants {
		roleGrant, err := NewRoleGrant(ctx, roleId, grant)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
		}
		newRoleGrants = append(newRoleGrants, roleGrant)
	}

	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope", roleId)))
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
			roleTicket, err := w.GetTicket(ctx, &role)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			// We need to update the role version as that's the aggregate
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = uint32(roleVersion) + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &roleOplogMsg)
			roleGrantOplogMsgs := make([]*oplog.Message, 0, len(newRoleGrants))
			if err := w.CreateItems(ctx, newRoleGrants, db.NewOplogMsgs(&roleGrantOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants"))
			}
			msgs = append(msgs, roleGrantOplogMsgs...)

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
	roleGrants := make([]*RoleGrant, 0, len(newRoleGrants))
	for _, grant := range newRoleGrants {
		roleGrants = append(roleGrants, grant.(*RoleGrant))
	}
	return roleGrants, nil
}

// DeleteRoleGrants deletes grants (as strings) from a role (roleId). The role's
// current db version must match the roleVersion or an error will be returned.
// Zero is not a valid value for the WithVersion option and will return an
// error.
func (r *Repository) DeleteRoleGrants(ctx context.Context, roleId string, roleVersion uint32, grants []string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeleteRoleGrants"
	if roleId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if len(grants) == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing grants")
	}
	if roleVersion == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	role := allocRole()
	role.PublicId = roleId

	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope to create metadata", roleId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
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
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = uint32(roleVersion) + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &roleOplogMsg)

			// Find existing grants
			roleGrants := []*RoleGrant{}
			if err := reader.SearchWhere(ctx, &roleGrants, "role_id = ?", []any{roleId}); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grants"))
			}
			found := map[string]bool{}
			for _, rg := range roleGrants {
				found[rg.CanonicalGrant] = true
			}

			// Check incoming grants to see if they exist and if so add to
			// delete slice
			deleteRoleGrants := make([]any, 0, len(grants))
			for _, grant := range grants {
				// Use a fake scope, just want to get out a canonical string
				perm, err := perms.Parse(ctx, "o_abcd1234", grant, perms.WithSkipFinalValidation(true))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("parsing grant string"))
				}
				// We don't have what they want to delete, so ignore it
				if !found[perm.CanonicalString()] {
					continue
				}

				roleGrant, err := NewRoleGrant(ctx, roleId, grant)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
				}
				deleteRoleGrants = append(deleteRoleGrants, roleGrant)
			}

			if len(deleteRoleGrants) == 0 {
				return nil
			}

			roleGrantOplogMsgs := make([]*oplog.Message, 0, len(deleteRoleGrants))
			rowsDeleted, err := w.DeleteItems(ctx, deleteRoleGrants, db.NewOplogMsgs(&roleGrantOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete role grant"))
			}
			if rowsDeleted != len(deleteRoleGrants) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("role grants deleted %d did not match request for %d", rowsDeleted, len(deleteRoleGrants)))
			}
			totalRowsDeleted = rowsDeleted
			msgs = append(msgs, roleGrantOplogMsgs...)

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String()},
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
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return totalRowsDeleted, nil
}

// SetRoleGrants sets grants on a role (roleId). The role's current db version
// must match the roleVersion or an error will be returned. Zero is not a valid
// value for the WithVersion option and will return an error.
func (r *Repository) SetRoleGrants(ctx context.Context, roleId string, roleVersion uint32, grants []string, _ ...Option) ([]*RoleGrant, int, error) {
	const op = "iam.(Repository).SetRoleGrants"
	if roleId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if roleVersion == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	// Explicitly set to zero clears, but treat nil as a mistake
	if grants == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing grants")
	}

	role := allocRole()
	role.PublicId = roleId

	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.

	// NOTE: Set calculation can safely take place out of the transaction since
	// we are using roleVersion to ensure that we end up operating on the same
	// set of data from this query to the final set in the transaction function

	// Find existing grants
	roleGrants := []*RoleGrant{}
	if err := r.reader.SearchWhere(ctx, &roleGrants, "role_id = ?", []any{roleId}); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for grants"))
	}
	found := map[string]*RoleGrant{}
	for _, rg := range roleGrants {
		found[rg.CanonicalGrant] = rg
	}

	// Check incoming grants to see if they exist and if so act appropriately
	currentRoleGrants := make([]*RoleGrant, 0, len(grants)+len(found))
	addRoleGrants := make([]any, 0, len(grants))
	deleteRoleGrants := make([]any, 0, len(grants))
	for _, grant := range grants {
		// Use a fake scope, just want to get out a canonical string
		perm, err := perms.Parse(ctx, "o_abcd1234", grant, perms.WithSkipFinalValidation(true))
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("error parsing grant string"))
		}
		canonicalString := perm.CanonicalString()

		rg, ok := found[canonicalString]
		if ok {
			// If we have an exact match, do nothing, we want to keep
			// it, but remove from found
			currentRoleGrants = append(currentRoleGrants, rg)
			delete(found, canonicalString)
			continue
		}

		// Not found, so add
		rg, err = NewRoleGrant(ctx, roleId, grant)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
		}
		addRoleGrants = append(addRoleGrants, rg)
		currentRoleGrants = append(currentRoleGrants, rg)
	}

	if len(found) > 0 {
		for _, rg := range found {
			deleteRoleGrants = append(deleteRoleGrants, rg)
		}
	}

	if len(addRoleGrants) == 0 && len(deleteRoleGrants) == 0 {
		return currentRoleGrants, db.NoRowsAffected, nil
	}

	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope", roleId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
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
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = roleVersion + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update role version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &roleOplogMsg)

			// Write the new ones in
			if len(addRoleGrants) > 0 {
				roleGrantOplogMsgs := make([]*oplog.Message, 0, len(addRoleGrants))
				if err := w.CreateItems(ctx, addRoleGrants, db.NewOplogMsgs(&roleGrantOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add grants during set"))
				}
				msgs = append(msgs, roleGrantOplogMsgs...)
			}

			// Anything we didn't take out of found needs to be removed
			if len(deleteRoleGrants) > 0 {
				roleGrantOplogMsgs := make([]*oplog.Message, 0, len(deleteRoleGrants))
				rowsDeleted, err := w.DeleteItems(ctx, deleteRoleGrants, db.NewOplogMsgs(&roleGrantOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete role grant"))
				}
				if rowsDeleted != len(deleteRoleGrants) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("role grants deleted %d did not match request for %d", rowsDeleted, len(deleteRoleGrants)))
				}
				totalRowsDeleted = rowsDeleted
				msgs = append(msgs, roleGrantOplogMsgs...)
			}

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String(), oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, roleTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			currentRoleGrants, err = r.ListRoleGrants(ctx, roleId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current role grants after set"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return currentRoleGrants, totalRowsDeleted, nil
}

// ListRoleGrants returns the grants for the roleId and supports the WithLimit
// option.
func (r *Repository) ListRoleGrants(ctx context.Context, roleId string, opt ...Option) ([]*RoleGrant, error) {
	const op = "iam.(Repository).ListRoleGrants"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	var roleGrants []*RoleGrant
	if err := r.list(ctx, &roleGrants, "role_id = ?", []any{roleId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup role grants"))
	}
	return roleGrants, nil
}

// ListRoleGrantScopes returns the grant scopes for the roleId and supports the WithLimit
// option.
func (r *Repository) ListRoleGrantScopes(ctx context.Context, roleId string, opt ...Option) ([]*RoleGrantScope, error) {
	const op = "iam.(Repository).ListRoleGrantScopes"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	var roleGrantScopes []*RoleGrantScope
	if err := r.list(ctx, &roleGrantScopes, "role_id = ?", []any{roleId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup role grant scopes"))
	}
	return roleGrantScopes, nil
}

func (r *Repository) GrantsForUser(ctx context.Context, userId string, _ ...Option) ([]perms.GrantTuple, error) {
	const op = "iam.(Repository).GrantsForUser"
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}

	const (
		anonUser = `where public_id in (?)`
		authUser = `where public_id in ('u_anon', 'u_auth', ?)`
	)

	var query string
	switch userId {
	case globals.AnonymousUserId:
		query = fmt.Sprintf(grantScopesQuery, anonUser)
	default:
		query = fmt.Sprintf(grantScopesQuery, authUser)
	}

	// First we need to get a mapping of roles and the scopes they affect; we'll
	// process those later
	type grantScopeValue struct {
		RoleId         string // The role id (iam_role.public_id)
		RoleScopeId    string // The scope of the role (iam_role.scope_id)
		GrantScopeId   string // A scope the grant is valid for
		CanonicalGrant string // The grant as a canonical string
	}
	var grantScopes []grantScopeValue
	rows, err := r.reader.Query(ctx, query, []any{userId})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	// The inner joins from the query mean we will have duplicate data for each
	// combination of grant and grant scope so these maps will allow us to
	// dedup
	roleGrants := map[string]map[string]struct{}{}
	roleScopes := map[string]map[string]bool{}

	for rows.Next() {
		var gs grantScopeValue
		if err := r.reader.ScanRows(ctx, rows, &gs); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		grantScopes = append(grantScopes, gs)

		// Dedup grants and scopes for each role
		{
			currGrants := roleGrants[gs.RoleId]
			if currGrants == nil {
				currGrants = make(map[string]struct{})
			}
			currGrants[gs.CanonicalGrant] = struct{}{}
			roleGrants[gs.RoleId] = currGrants

			// We are simply pre-creating the maps; the default values of false
			// will be what we want later
			currScopes := roleScopes[gs.RoleId]
			if currScopes == nil {
				currScopes = make(map[string]bool)
			}
			roleScopes[gs.RoleId] = currScopes
		}
	}
	// log.Println(fmt.Sprintf("grant scopes: %s", pretty.Sprint(grantScopes)))

	// Now we start interpreting and fetching scopes as we go. Ideally we'd
	// collapse this into a single query but we need to keep the role
	// association so any results would have to be role/scope tuples.
	grants := make([]perms.GrantTuple, 0, len(grantScopes))
	queryBase := "select public_id from iam_scope where"

	populateRoleGrants := func(roleId string, scopes []string) {
		// log.Println("populateRoleGrants", "roleId", roleId, "scopes", scopes)
		for grant := range roleGrants[roleId] {
			for _, scp := range scopes {
				grants = append(grants, perms.GrantTuple{
					RoleId:  roleId,
					ScopeId: scp,
					Grant:   grant,
				})
			}
		}
	}

	for _, gs := range grantScopes {
		currScopes := roleScopes[gs.RoleId]
		if currScopes[gs.GrantScopeId] {
			// We've already processed this grant scope for this role, so skip
			continue
		}
		currScopes[gs.GrantScopeId] = true
		roleScopes[gs.RoleId] = currScopes

		// log.Println(pretty.Sprint(roleScopes))

		switch gs.GrantScopeId {
		case "descendants", "children":
			var query string
			args := make([]any, 0, 1)

			if gs.GrantScopeId == "descendants" {
				if gs.RoleScopeId != scope.Global.String() {
					return nil, fmt.Errorf("found descendants grant scope in role %q with scope %q but it is only valid for global scope; this is a database integrity issue", gs.RoleId, gs.RoleScopeId)
				}
				// This can only be global scope, so we need everything that isn't
				// global (since "global" or "this" would be a separate scope ID
				// we'll loop through later)
				query = fmt.Sprintf("%s public_id != ?", queryBase)
				args = append(args, "global")
			} else {
				query = fmt.Sprintf("%s parent_id = ?", queryBase)
				args = append(args, gs.RoleScopeId)
			}

			rows, err = r.reader.Query(ctx, query, args)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			scopes := make([]string, 0, len(grantScopes))
			defer rows.Close()
			for rows.Next() {
				if err := r.reader.ScanRows(ctx, rows, &scopes); err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
			}
			// log.Println(fmt.Sprintf("scopes in %s", gs.GrantScopeId), scopes)
			populateRoleGrants(gs.RoleId, scopes)

		default: // bare scope ID or "this"
			scopeId := gs.GrantScopeId
			if scopeId == "this" {
				scopeId = gs.RoleScopeId
			}
			// It's a bare scope ID
			populateRoleGrants(gs.RoleId, []string{scopeId})
		}

		// log.Println("current grants", pretty.Sprint(grants))
	}

	return grants, nil
}

func (r *Repository) OldGrantsForUser(ctx context.Context, userId string, _ ...Option) ([]perms.GrantTuple, error) {
	const op = "iam.(Repository).GrantsForUser"
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}

	const (
		anonUser = `where public_id in (?)`
		authUser = `where public_id in ('u_anon', 'u_auth', ?)`
	)

	var query string
	switch userId {
	case globals.AnonymousUserId:
		query = fmt.Sprintf(oldGrantsQuery, anonUser)
	default:
		query = fmt.Sprintf(oldGrantsQuery, authUser)
	}

	var grants []perms.GrantTuple
	rows, err := r.reader.Query(ctx, query, []any{userId})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()
	for rows.Next() {
		var g perms.GrantTuple
		if err := r.reader.ScanRows(ctx, rows, &g); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		grants = append(grants, g)
	}
	return grants, nil
}
