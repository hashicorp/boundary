package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/perms"
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

	_, err := r.writer.DoTx(
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

			s, err := role.GetScope(ctx, r.reader)
			if err != nil {
				return fmt.Errorf("add role grants: unable to get role %s scope: %w", roleId, err)
			}

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{s.PublicId},
				"scope-type":         []string{s.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, roleTicket, metadata, msgs); err != nil {
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

	var totalRowsDeleted int
	_, err := r.writer.DoTx(
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
				perm, err := perms.Parse("o_abcd1234", "", grant)
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

			s, err := role.GetScope(ctx, r.reader)
			if err != nil {
				return fmt.Errorf("delete role grants: unable to get role %s scope: %w", roleId, err)
			}

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String()},
				"scope-id":           []string{s.PublicId},
				"scope-type":         []string{s.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, roleTicket, metadata, msgs); err != nil {
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
		return nil, 0, fmt.Errorf("set role grants: missing role id %w", db.ErrInvalidParameter)
	}
	if roleVersion == 0 {
		return nil, 0, fmt.Errorf("set role grants: version cannot be zero: %w", db.ErrInvalidParameter)
	}

	// Explicitly set to zero clears, but treat nil as a mistake
	if grants == nil {
		return nil, 0, fmt.Errorf("set role grants: nil grants: %w", db.ErrNilParameter)
	}

	role := allocRole()
	role.PublicId = roleId

	// NOTE: Set calculation can safely take place out of the transaction since
	// we are using roleVersion to ensure that we end up operating on the same
	// set of data from this query to the final set in the transaction function

	// Find existing grants
	roleGrants := []*RoleGrant{}
	if err := r.reader.SearchWhere(ctx, &roleGrants, "role_id = ?", []interface{}{roleId}); err != nil {
		return nil, 0, fmt.Errorf("set role grants: unable to search for grants: %w", err)
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
		perm, err := perms.Parse("o_abcd1234", "", grant)
		if err != nil {
			return nil, 0, fmt.Errorf("set role grants: error parsing grant string: %w", err)
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
			return nil, 0, fmt.Errorf("set role grants: unable to create in memory role grant: %w", err)
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
		return currentRoleGrants, 0, nil
	}

	var totalRowsDeleted int
	_, err := r.writer.DoTx(
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

			s, err := role.GetScope(ctx, r.reader)
			if err != nil {
				return fmt.Errorf("set role grants: unable to get role %s scope: %w", roleId, err)
			}

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String(), oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{s.PublicId},
				"scope-type":         []string{s.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, roleTicket, metadata, msgs); err != nil {
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
