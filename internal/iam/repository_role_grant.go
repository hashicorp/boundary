package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
)

// AddRoleGrant will add role grants associated with the role ID in the
// repository. No options are currently supported. Zero is not a valid value for
// the WithVersion option and will return an error.
func (r *Repository) AddRoleGrants(ctx context.Context, roleId string, roleVersion uint32, grants []string, opt ...Option) ([]*RoleGrant, error) {
	if roleId == "" {
		return nil, fmt.Errorf("add role grants: missing role id %w", db.ErrInvalidParameter)
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf("add role grants: missing grants: %w", db.ErrInvalidParameter)
	}
	if roleVersion == 0 {
		return nil, fmt.Errorf("add role grants: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	role := allocRole()
	role.PublicId = roleId

	newRoleGrants := make([]interface{}, 0, len(grants))
	for _, grant := range grants {
		roleGrant, err := NewRoleGrant(roleId, grant)
		if err != nil {
			return nil, fmt.Errorf("add role grants: unable to create in memory role grant: %w", err)
		}
		newRoleGrants = append(newRoleGrants, roleGrant)
	}

	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("add role grants: unable to get role %s scope: %w", roleId, err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("add role grants: unable to get oplog wrapper: %w", err)
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(&role)
			if err != nil {
				return fmt.Errorf("unable to get ticket: %w", err)
			}

			// We need to update the role version as that's the aggregate
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = uint32(roleVersion) + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return fmt.Errorf("unable to update role version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("updated role and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &roleOplogMsg)
			roleGrantOplogMsgs := make([]*oplog.Message, 0, len(newRoleGrants))
			if err := w.CreateItems(ctx, newRoleGrants, db.NewOplogMsgs(&roleGrantOplogMsgs)); err != nil {
				return fmt.Errorf("unable to add grants: %w", err)
			}
			msgs = append(msgs, roleGrantOplogMsgs...)

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, roleTicket, metadata, msgs); err != nil {
				return fmt.Errorf("unable to write oplog: %w", err)
			}

			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("add role grants: error creating grants: %w", err)
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
func (r *Repository) DeleteRoleGrants(ctx context.Context, roleId string, roleVersion uint32, grants []string, opt ...Option) (int, error) {
	if roleId == "" {
		return 0, fmt.Errorf("delete role grants: missing role id %w", db.ErrInvalidParameter)
	}
	if len(grants) == 0 {
		return 0, fmt.Errorf("delete role grants: missing grants: %w", db.ErrInvalidParameter)
	}
	if roleVersion == 0 {
		return 0, fmt.Errorf("delete role grants: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	role := allocRole()
	role.PublicId = roleId

	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete role grants: unable to get role %s scope to create metadata: %w", roleId, err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete role grants: unable to get oplog wrapper: %w", err)
	}

	var totalRowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(&role)
			if err != nil {
				return fmt.Errorf("delete role grants: unable to get ticket: %w", err)
			}
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = uint32(roleVersion) + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return fmt.Errorf("delete role grants: unable to update role version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("delete roles grants: updated role and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &roleOplogMsg)

			// Find existing grants
			roleGrants := []*RoleGrant{}
			if err := reader.SearchWhere(ctx, &roleGrants, "role_id = ?", []interface{}{roleId}); err != nil {
				return fmt.Errorf("delete role grants: unable to search for grants: %w", err)
			}
			found := map[string]bool{}
			for _, rg := range roleGrants {
				found[rg.CanonicalGrant] = true
			}

			// Check incoming grants to see if they exist and if so add to
			// delete slice
			deleteRoleGrants := make([]interface{}, 0, len(grants))
			for _, grant := range grants {
				// Use a fake scope, just want to get out a canonical string
				perm, err := perms.Parse("o_abcd1234", grant, perms.WithSkipFinalValidation(true))
				if err != nil {
					return fmt.Errorf("delete role grants: error parsing grant string: %w", err)
				}
				// We don't have what they want to delete, so ignore it
				if !found[perm.CanonicalString()] {
					continue
				}

				roleGrant, err := NewRoleGrant(roleId, grant)
				if err != nil {
					return fmt.Errorf("delete role grants: unable to create in memory role grant: %w", err)
				}
				deleteRoleGrants = append(deleteRoleGrants, roleGrant)
			}

			if len(deleteRoleGrants) == 0 {
				return nil
			}

			roleGrantOplogMsgs := make([]*oplog.Message, 0, len(deleteRoleGrants))
			rowsDeleted, err := w.DeleteItems(ctx, deleteRoleGrants, db.NewOplogMsgs(&roleGrantOplogMsgs))
			if err != nil {
				return fmt.Errorf("delete role grants: unable to delete role grant: %w", err)
			}
			if rowsDeleted != len(deleteRoleGrants) {
				return fmt.Errorf("delete role grants: role grants deleted %d did not match request for %d", rowsDeleted, len(deleteRoleGrants))
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
				return fmt.Errorf("delete role grants: unable to write oplog: %w", err)
			}

			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete role grants: error deleting role grants: %w", err)
	}
	return totalRowsDeleted, nil
}

// SetRoleGrants sets grants on a role (roleId). The role's current db version
// must match the roleVersion or an error will be returned. Zero is not a valid
// value for the WithVersion option and will return an error.
func (r *Repository) SetRoleGrants(ctx context.Context, roleId string, roleVersion uint32, grants []string, opt ...Option) ([]*RoleGrant, int, error) {
	if roleId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("set role grants: missing role id %w", db.ErrInvalidParameter)
	}
	if roleVersion == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("set role grants: version cannot be zero: %w", db.ErrInvalidParameter)
	}

	// Explicitly set to zero clears, but treat nil as a mistake
	if grants == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set role grants: nil grants: %w", db.ErrInvalidParameter)
	}

	role := allocRole()
	role.PublicId = roleId

	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.

	// NOTE: Set calculation can safely take place out of the transaction since
	// we are using roleVersion to ensure that we end up operating on the same
	// set of data from this query to the final set in the transaction function

	// Find existing grants
	roleGrants := []*RoleGrant{}
	if err := r.reader.SearchWhere(ctx, &roleGrants, "role_id = ?", []interface{}{roleId}); err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set role grants: unable to search for grants: %w", err)
	}
	found := map[string]*RoleGrant{}
	for _, rg := range roleGrants {
		found[rg.CanonicalGrant] = rg
	}

	// Check incoming grants to see if they exist and if so act appropriately
	currentRoleGrants := make([]*RoleGrant, 0, len(grants)+len(found))
	addRoleGrants := make([]interface{}, 0, len(grants))
	deleteRoleGrants := make([]interface{}, 0, len(grants))
	for _, grant := range grants {
		// Use a fake scope, just want to get out a canonical string
		perm, err := perms.Parse("o_abcd1234", grant, perms.WithSkipFinalValidation(true))
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set role grants: error parsing grant string: %w", err)
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
		rg, err = NewRoleGrant(roleId, grant)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set role grants: unable to create in memory role grant: %w", err)
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
		return nil, db.NoRowsAffected, fmt.Errorf("set role grants: unable to get role %s scope: %w", roleId, err)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set role grants: unable to get oplog wrapper: %w", err)
	}

	var totalRowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(&role)
			if err != nil {
				return fmt.Errorf("set role grants: unable to get ticket: %w", err)
			}
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = roleVersion + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return fmt.Errorf("set role grants: unable to update role version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("set roles grants: updated role and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &roleOplogMsg)

			// Write the new ones in
			if len(addRoleGrants) > 0 {
				roleGrantOplogMsgs := make([]*oplog.Message, 0, len(addRoleGrants))
				if err := w.CreateItems(ctx, addRoleGrants, db.NewOplogMsgs(&roleGrantOplogMsgs)); err != nil {
					return fmt.Errorf("unable to add grants during set: %w", err)
				}
				msgs = append(msgs, roleGrantOplogMsgs...)
			}

			// Anything we didn't take out of found needs to be removed
			if len(deleteRoleGrants) > 0 {
				roleGrantOplogMsgs := make([]*oplog.Message, 0, len(deleteRoleGrants))
				rowsDeleted, err := w.DeleteItems(ctx, deleteRoleGrants, db.NewOplogMsgs(&roleGrantOplogMsgs))
				if err != nil {
					return fmt.Errorf("set role grants: unable to delete role grant: %w", err)
				}
				if rowsDeleted != len(deleteRoleGrants) {
					return fmt.Errorf("set role grants: role grants deleted %d did not match request for %d", rowsDeleted, len(deleteRoleGrants))
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
				return fmt.Errorf("set role grants: unable to write oplog: %w", err)
			}

			currentRoleGrants, err = r.ListRoleGrants(ctx, roleId)
			if err != nil {
				return fmt.Errorf("set role grants: unable to retrieve current role grants after set: %w", err)
			}

			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set role grants: error set role grants: %w", err)
	}
	return currentRoleGrants, totalRowsDeleted, nil
}

// ListRoleGrants returns the grants for the roleId and supports the WithLimit
// option.
func (r *Repository) ListRoleGrants(ctx context.Context, roleId string, opt ...Option) ([]*RoleGrant, error) {
	if roleId == "" {
		return nil, fmt.Errorf("add role grants: missing role id %w", db.ErrInvalidParameter)
	}
	var roleGrants []*RoleGrant
	if err := r.list(ctx, &roleGrants, "role_id = ?", []interface{}{roleId}, opt...); err != nil {
		return nil, fmt.Errorf("lookup role grants: unable to lookup role grants: %w", err)
	}
	return roleGrants, nil
}

func (r *Repository) GrantsForUser(ctx context.Context, userId string, opt ...Option) ([]perms.GrantPair, error) {
	if userId == "" {
		return nil, fmt.Errorf("get grants for user: missing user id: %w", db.ErrInvalidParameter)
	}

	const (
		anonUser    = `where public_id in ($1)`
		authUser    = `where public_id in ('u_anon', 'u_auth', $1)`
		grantsQuery = `
with
users (id) as (
  select public_id
    from iam_user
  %s -- anonUser || authUser
),
user_groups (id) as (
  select group_id
    from iam_group_member_user,
         users
   where member_id in (users.id)
),
group_roles (role_id) as (
  select role_id
    from iam_group_role,
         user_groups
   where principal_id in (user_groups.id)
),
user_roles (role_id) as (
  select role_id
    from iam_user_role,
         users
   where principal_id in (users.id)
),
user_group_roles (role_id) as (
  select role_id
    from group_roles
   union
  select role_id
    from user_roles
),
roles (role_id, grant_scope_id) as (
  select iam_role.public_id,
         iam_role.grant_scope_id
    from iam_role,
         user_group_roles
   where public_id in (user_group_roles.role_id)
),
final (role_scope, role_grant) as (
  select roles.grant_scope_id,
         iam_role_grant.canonical_grant
    from roles
   inner
    join iam_role_grant
      on roles.role_id = iam_role_grant.role_id
)
select role_scope as scope_id, role_grant as grant from final;
	`
	)

	var query string
	switch userId {
	case "u_anon":
		query = fmt.Sprintf(grantsQuery, anonUser)
	default:
		query = fmt.Sprintf(grantsQuery, authUser)
	}

	var grants []perms.GrantPair
	rows, err := r.reader.Query(ctx, query, []interface{}{userId})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var g perms.GrantPair
		if err := r.reader.ScanRows(rows, &g); err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, nil
}
