// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/lib/pq"
)

// AddRoleGrants will add role grants associated with the role ID in the
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

	newRoleGrants := make([]*RoleGrant, 0, len(grants))
	for _, grant := range grants {
		roleGrant, err := NewRoleGrant(ctx, roleId, grant)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory role grant"))
		}
		newRoleGrants = append(newRoleGrants, roleGrant)
	}

	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id", roleId)))
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
			roleTicket, err := w.GetTicket(ctx, updatedRole)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
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
	return newRoleGrants, nil
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
	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id", roleId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
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
			roleTicket, err := w.GetTicket(ctx, updatedRole)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
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
			deleteRoleGrants := make([]*RoleGrant, 0, len(grants))
			for _, grant := range grants {
				// Use a fake scope, just want to get out a canonical string
				perm, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: "o_abcd1234", GrantScopeId: "o_abcd1234", Grant: grant}, perms.WithSkipFinalValidation(true))
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
	addRoleGrants := make([]*RoleGrant, 0, len(grants))
	deleteRoleGrants := make([]*RoleGrant, 0, len(grants))
	for _, grant := range grants {
		// Use a fake scope, just want to get out a canonical string
		perm, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: "o_abcd1234", GrantScopeId: "o_abcd1234", Grant: grant}, perms.WithSkipFinalValidation(true))
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
	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope id", roleId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
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
			roleTicket, err := w.GetTicket(ctx, updatedRole)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
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
				"scope-id":           []string{scp.PublicId},
				"scope-type":         []string{scp.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, roleTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			currentRoleGrants, err = r.ListRoleGrants(ctx, roleId, WithReaderWriter(reader, w))
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

type grantsForUserResults struct {
	// roleId is the public ID of the role.
	roleId string
	// roleScopeId is the scope ID of the role.
	roleScopeId string
	// roleParentScopeId is the parent scope ID of the role.
	roleParentScopeId string
	// grantScope is the grant scope of the role.
	// The valid values are: "individual", "children" and "descendants".
	grantScope string
	// grantThisRoleScope is a boolean that indicates if the role has a grant
	// for itself aka "this" or "individual" scope.
	grantThisRoleScope bool
	// individualGrantScopes represents the individual grant scopes for the role.
	// This is a slice of strings that may be empty if the role does
	// not have individual grants.
	individualGrantScopes []string
	// canonicalGrants represents the canonical grants for the role.
	// This is a slice of strings that may be empty if the role does
	// not have canonical grants associated with it.
	canonicalGrants []string
}

// GrantsForUser returns perms.GrantTuples associated to a userId scoped down to the requested scope and resource type.
// Use WithRecursive option to indicate that the request is a recursive list request
// Supported options: WithRecursive
func (r *Repository) GrantsForUser(ctx context.Context, userId string, res []resource.Type, reqScopeId string, opt ...Option) (perms.GrantTuples, error) {
	const op = "iam.(Repository).GrantsForUser"
	if userId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	if res == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing resource type")
	}
	if slices.Contains(res, resource.Unknown) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type cannot be unknown")
	}
	if slices.Contains(res, resource.All) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type cannot be all")
	}
	switch {
	case strings.HasPrefix(reqScopeId, globals.GlobalPrefix):
	case strings.HasPrefix(reqScopeId, globals.OrgPrefix):
	case strings.HasPrefix(reqScopeId, globals.ProjectPrefix):
	case reqScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing request scope id")
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "request scope must be global scope, an org scope, or a project scope")
	}

	// Determine which query to use based on the resources, request scope, and recursive option
	opts := getOpts(opt...)
	query, err := r.resolveQuery(ctx, res, reqScopeId, opts.withRecursive)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to resolve query"))
	}

	// Execute the query to get the user's grants
	var (
		args      []any
		userIds   []string
		resources []string
	)
	switch userId {
	case globals.AnonymousUserId:
		userIds = []string{globals.AnonymousUserId}
	default:
		userIds = []string{globals.AnonymousUserId, globals.AnyAuthenticatedUserId, userId}
	}

	resources = []string{resource.Unknown.String(), resource.All.String()}
	for _, res := range res {
		resources = append(resources, res.String())
	}

	args = append(args,
		sql.Named("user_ids", pq.Array(userIds)),
		sql.Named("resources", pq.Array(resources)),
		sql.Named("request_scope_id", reqScopeId),
	)

	var grants []grantsForUserResults
	rows, err := r.reader.Query(ctx, query, args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()
	for rows.Next() {
		var g grantsForUserResults
		if err := rows.Scan(
			&g.roleId,
			&g.roleScopeId,
			&g.roleParentScopeId,
			&g.grantScope,
			&g.grantThisRoleScope,
			pq.Array(&g.individualGrantScopes),
			pq.Array(&g.canonicalGrants),
		); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	ret := make(perms.GrantTuples, 0, len(grants))
	for _, grant := range grants {

		if grant.grantScope != globals.GrantScopeIndividual {
			for _, canonicalGrant := range grant.canonicalGrants {
				gt := perms.GrantTuple{
					RoleId:            grant.roleId,
					RoleScopeId:       grant.roleScopeId,
					RoleParentScopeId: grant.roleParentScopeId,
					GrantScopeId:      grant.grantScope,
					Grant:             canonicalGrant,
				}
				ret = append(ret, gt)
			}
		}

		if grant.grantThisRoleScope {
			switch {
			case opts.withRecursive:
				// Recursive requests can list the entire scope tree at any request scope
				fallthrough
			case reqScopeId == grant.roleScopeId:
				// Non-recursive requests' role scope must match the request scope
				for _, canonicalGrant := range grant.canonicalGrants {
					gt := perms.GrantTuple{
						RoleId:            grant.roleId,
						RoleScopeId:       grant.roleScopeId,
						RoleParentScopeId: grant.roleParentScopeId,
						GrantScopeId:      grant.roleScopeId,
						Grant:             canonicalGrant,
					}
					ret = append(ret, gt)
				}
			}
		}

		// loop over grants creating tuple with grant_scope = s.ScopeId
		for _, individualGrantScope := range grant.individualGrantScopes {
			for _, canonicalGrant := range grant.canonicalGrants {
				gt := perms.GrantTuple{
					RoleId:            grant.roleId,
					RoleScopeId:       grant.roleScopeId,
					RoleParentScopeId: grant.roleParentScopeId,
					GrantScopeId:      individualGrantScope,
					Grant:             canonicalGrant,
				}
				ret = append(ret, gt)
			}
		}
	}
	return ret, nil
}

func (r *Repository) resolveQuery(
	ctx context.Context,
	res []resource.Type,
	reqScopeId string,
	isRecursive bool,
) (string, error) {
	const op = "iam.(Repository).resolveQuery"
	if res == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing resource type")
	}
	if slices.Contains(res, resource.Unknown) {
		return "", errors.New(ctx, errors.InvalidParameter, op, "resource type cannot be unknown")
	}
	if slices.Contains(res, resource.All) {
		return "", errors.New(ctx, errors.InvalidParameter, op, "resource type cannot be all")
	}
	if reqScopeId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing request scope id")
	}

	// Use the largest set of allowed scopes for the given resources
	var resourceAllowedIn []scope.Type
	for _, re := range res {
		a, err := scope.AllowedIn(ctx, re)
		if err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
		if len(a) > len(resourceAllowedIn) {
			resourceAllowedIn = a
		}
	}

	// Recursive query
	if isRecursive {
		return grantsForUserRecursiveQuery, nil
	}

	// Non-recursive queries
	switch {
	case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global}):
		if reqScopeId != globals.GlobalPrefix {
			return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("request scope id must be global for %s resources", res))
		}
		return grantsForUserGlobalResourcesQuery, nil
	case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org}):
		switch {
		case strings.HasPrefix(reqScopeId, globals.GlobalPrefix):
			return grantsForUserGlobalResourcesQuery, nil
		case strings.HasPrefix(reqScopeId, globals.OrgPrefix):
			return grantsForUserOrgResourcesQuery, nil
		default:
			return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("request scope id must be global or org for %s resources", res))
		}
	case slices.Equal(resourceAllowedIn, []scope.Type{scope.Global, scope.Org, scope.Project}):
		switch {
		case strings.HasPrefix(reqScopeId, globals.GlobalPrefix):
			return grantsForUserGlobalResourcesQuery, nil
		case strings.HasPrefix(reqScopeId, globals.OrgPrefix):
			return grantsForUserOrgResourcesQuery, nil
		case strings.HasPrefix(reqScopeId, globals.ProjectPrefix):
			return grantsForUserProjectResourcesQuery, nil
		default:
			return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid scope id %s", reqScopeId))
		}
	case slices.Equal(resourceAllowedIn, []scope.Type{scope.Project}):
		if !strings.HasPrefix(reqScopeId, globals.ProjectPrefix) {
			return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("request scope id must be project for %s resources", res))
		}
		return grantsForUserProjectResourcesQuery, nil
	}
	return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid resource type: %v", res))
}
