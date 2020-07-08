package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

func scopeAndIdForRole(scopeId, principalId string) (string, string, error) {
	switch strings.Count(principalId, ":") {
	case 0:
		return scopeId, principalId, nil
	case 1:
		substrs := strings.Split(principalId, ":")
		if substrs[0] == scopeId {
			return "", "", fmt.Errorf("principal roles scope and id fetching: redundant scope ID set: %w", db.ErrInvalidParameter)
		}
		return substrs[0], substrs[1], nil
	default:
		return "", "", fmt.Errorf("principal roles scope and id fetching: invalid principal id, contains too many colons: %w", db.ErrInvalidParameter)
	}
}

// AddPrincipalRoles provides the ability to add principals (userIds and
// groupIds) to a role (roleId).  The role's current db version must match the
// roleVersion or an error will be returned.  The roles and groups must be in
// the same scope.  User can only be added to roles which are within the user's
// organization, or the role is within a project within the user's organization.
func (r *Repository) AddPrincipalRoles(ctx context.Context, roleId string, roleVersion int, userIds, groupIds []string, opt ...Option) ([]PrincipalRole, error) {
	// NOTE - we are intentionally not going to check that the scopes are
	// correct for the userIds and groupIds, given the roleId.  We are going to
	// rely on the database constraints and triggers to maintain the integrity
	// of these scope relationships.  The users and role need to either be in
	// the same organization or the role needs to be in a project of the user's
	// org.  The groups and role have to be in the same scope (org or project).
	// There are constraints and triggers to enforce these relationships.
	if roleId == "" {
		return nil, fmt.Errorf("add principal roles: missing role id: %w", db.ErrInvalidParameter)
	}
	if len(userIds) == 0 && len(groupIds) == 0 {
		return nil, fmt.Errorf("add principal roles: missing either user or groups to add: %w", db.ErrInvalidParameter)
	}

	role := allocRole()
	role.PublicId = roleId
	roleScope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("add principal roles: unable to get role %s scope: %w", roleId, err)
	}

	newUserRoles := make([]interface{}, 0, len(userIds))
	for _, id := range userIds {
		scopeId, userId, err := scopeAndIdForRole(role.ScopeId, id)
		if err != nil {
			return nil, err
		}
		usrRole, err := NewUserRole(scopeId, roleId, userId)
		if err != nil {
			return nil, fmt.Errorf("add principal roles: unable to create in memory user role: %w", err)
		}
		newUserRoles = append(newUserRoles, usrRole)
	}
	newGrpRoles := make([]interface{}, 0, len(groupIds))
	for _, id := range groupIds {
		scopeId, groupId, err := scopeAndIdForRole(role.ScopeId, id)
		if err != nil {
			return nil, err
		}
		grpRole, err := NewGroupRole(scopeId, roleId, groupId)
		if err != nil {
			return nil, fmt.Errorf("add principal roles: unable to create in memory group role: %w", err)
		}
		newGrpRoles = append(newGrpRoles, grpRole)
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			roleTicket, err := w.GetTicket(&role)
			if err != nil {
				return fmt.Errorf("add principal roles: unable to get ticket: %w", err)
			}
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = uint32(roleVersion) + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(roleVersion))
			if err != nil {
				return fmt.Errorf("add principal roles: unable to update role version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("add principal roles: updated role and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &roleOplogMsg)
			if len(newUserRoles) > 0 {
				userOplogMsgs := make([]*oplog.Message, 0, len(newUserRoles))
				if err := w.CreateItems(ctx, newUserRoles, db.NewOplogMsgs(&userOplogMsgs)); err != nil {
					return fmt.Errorf("add principal roles: unable to add users: %w", err)
				}
				msgs = append(msgs, userOplogMsgs...)
			}
			if len(newGrpRoles) > 0 {
				grpOplogMsgs := make([]*oplog.Message, 0, len(newGrpRoles))
				if err := w.CreateItems(ctx, newGrpRoles, db.NewOplogMsgs(&grpOplogMsgs)); err != nil {
					return fmt.Errorf("add principal roles: unable to add groups: %w", err)
				}
				msgs = append(msgs, grpOplogMsgs...)
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{roleScope.PublicId},
				"scope-type":         []string{roleScope.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, roleTicket, metadata, msgs); err != nil {
				return fmt.Errorf("add principal roles: unable to write oplog: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("add principal roles: error creating roles: %w", err)
	}
	principalRoles := make([]PrincipalRole, 0, len(newUserRoles)+len(newUserRoles))
	for _, role := range newUserRoles {
		principalRoles = append(principalRoles, role.(*UserRole))
	}
	for _, role := range newGrpRoles {
		principalRoles = append(principalRoles, role.(*GroupRole))
	}
	return principalRoles, nil
}

// SetPrincipalRoles will set the role's principals. Set add and/or delete
// principals as need to reconcile the existing principals with the principals
// requested. If both userIds and groupIds are empty, the principal roles will
// be cleared.
func (r *Repository) SetPrincipalRoles(ctx context.Context, roleId string, roleVersion int, userIds, groupIds []string, opt ...Option) ([]PrincipalRole, int, error) {
	// NOTE - we are intentionally not going to check that the scopes are
	// correct for the userIds and groupIds, given the roleId.  We are going to
	// rely on the database constraints and triggers to maintain the integrity
	// of these scope relationships.  The users and role need to either be in
	// the same organization or the role needs to be in a project of the user's
	// org.  The groups and role have to be in the same scope (org or project).
	// There are constraints and triggers to enforce these relationships.
	if roleId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("set principal roles: missing role id: %w", db.ErrInvalidParameter)
	}
	role := allocRole()
	role.PublicId = roleId
	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set principal roles: unable to get role %s scope: %w", roleId, err)
	}
	// it's "safe" to do this lookup outside the DoTx transaction because we
	// have a roleVersion so the principals can’t change without the version
	// changing.
	toSet, err := r.principalsToSet(ctx, &role, userIds, groupIds)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set principal roles: unable to determine set: %w", err)
	}

	// handle no change to existing principal roles
	if len(toSet.unchangedPrincipalRoles) > 0 {
		return toSet.unchangedPrincipalRoles, db.NoRowsAffected, nil
	}

	var currentPrincipals []PrincipalRole
	var totalRowsAffected int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			// we need a roleTicket, which won't be redeemed until all the other
			// writes are successful.  We can't just use a single ticket because
			// we need to write oplog entries for deletes and adds
			roleTicket, err := w.GetTicket(&role)
			if err != nil {
				return fmt.Errorf("set principal roles: unable to get ticket for role: %w", err)
			}
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = uint32(roleVersion) + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(roleVersion))
			if err != nil {
				return fmt.Errorf("set principal roles: unable to update role version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("set principal roles: updated role and %d rows updated", rowsUpdated)
			}
			msgs := make([]*oplog.Message, 0, 5)
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{roleId},
			}
			msgs = append(msgs, &roleOplogMsg)

			if len(toSet.deleteUserRoles) > 0 || len(toSet.deleteGroupRoles) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
				if len(toSet.deleteUserRoles) > 0 {
					userOplogMsgs := make([]*oplog.Message, 0, len(toSet.deleteUserRoles))
					rowsDeleted, err := w.DeleteItems(ctx, toSet.deleteUserRoles, db.NewOplogMsgs(&userOplogMsgs))
					if err != nil {
						return fmt.Errorf("set principal roles: unable to delete user roles: %w", err)
					}
					if rowsDeleted != len(toSet.deleteUserRoles) {
						return fmt.Errorf("set principal roles: user roles deleted %d did not match request for %d", rowsDeleted, len(toSet.deleteUserRoles))
					}
					totalRowsAffected += rowsDeleted
					msgs = append(msgs, userOplogMsgs...)
				}
				if len(toSet.deleteGroupRoles) > 0 {
					grpOplogMsgs := make([]*oplog.Message, 0, len(toSet.deleteGroupRoles))
					rowsDeleted, err := w.DeleteItems(ctx, toSet.deleteGroupRoles, db.NewOplogMsgs(&grpOplogMsgs))
					if err != nil {
						return fmt.Errorf("set principal roles: unable to delete groups: %w", err)
					}
					if rowsDeleted != len(toSet.deleteGroupRoles) {
						return fmt.Errorf("set principal roles: group roles deleted %d did not match request for %d", rowsDeleted, len(toSet.deleteGroupRoles))
					}
					totalRowsAffected += rowsDeleted
					msgs = append(msgs, grpOplogMsgs...)
				}
			}
			if len(toSet.addUserRoles) > 0 || len(toSet.addGroupRoles) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
				if len(toSet.addUserRoles) > 0 {
					userOplogMsgs := make([]*oplog.Message, 0, len(toSet.addUserRoles))
					if err := w.CreateItems(ctx, toSet.addUserRoles, db.NewOplogMsgs(&userOplogMsgs)); err != nil {
						return fmt.Errorf("set principal roles: unable to add users: %w", err)
					}
					totalRowsAffected += len(toSet.addUserRoles)
					msgs = append(msgs, userOplogMsgs...)
				}
				if len(toSet.addGroupRoles) > 0 {
					grpOplogMsgs := make([]*oplog.Message, 0, len(toSet.addGroupRoles))
					if err := w.CreateItems(ctx, toSet.addGroupRoles, db.NewOplogMsgs(&grpOplogMsgs)); err != nil {
						return fmt.Errorf("set principal roles: unable to add groups: %w", err)
					}
					totalRowsAffected += len(toSet.addGroupRoles)
					msgs = append(msgs, grpOplogMsgs...)
				}
			}
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, roleTicket, metadata, msgs); err != nil {
				return fmt.Errorf("set principal roles: unable to write oplog for additions: %w", err)
			}

			return nil
		})
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set principal roles: unable to set principals: %w", err)
	}

	// The view isn't updated until after the transaction completes, so we have
	// to do the final listing after the transaction finishes
	currentPrincipals, err = r.ListPrincipalRoles(ctx, roleId)
	if err != nil {
		return nil, 0, fmt.Errorf("set principal roles: unable to retrieve current principal roles after sets: %w", err)
	}

	return currentPrincipals, totalRowsAffected, nil
}

// DeletePrincipalRoles principals (userIds and/or groupIds) from a role
// (roleId). The role's current db version must match the roleVersion or an
// error will be returned.
func (r *Repository) DeletePrincipalRoles(ctx context.Context, roleId string, roleVersion int, userIds, groupIds []string, opt ...Option) (int, error) {
	if roleId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete principal roles: missing role id: %w", db.ErrInvalidParameter)
	}
	if len(userIds) == 0 && len(groupIds) == 0 {
		return db.NoRowsAffected, fmt.Errorf("delete principal roles: missing either user or groups to delete: %w", db.ErrInvalidParameter)
	}
	role := allocRole()
	role.PublicId = roleId
	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete principal roles: unable to get role %s scope to create metadata: %w", roleId, err)
	}
	deleteUserRoles := make([]interface{}, 0, len(userIds))
	for _, id := range userIds {
		scopeId, userId, err := scopeAndIdForRole(role.ScopeId, id)
		if err != nil {
			return 0, err
		}
		usrRole, err := NewUserRole(scopeId, roleId, userId)
		if err != nil {
			return db.NoRowsAffected, fmt.Errorf("delete principal roles: unable to create in memory user role: %w", err)
		}
		deleteUserRoles = append(deleteUserRoles, usrRole)
	}
	deleteGrpRoles := make([]interface{}, 0, len(groupIds))
	for _, id := range groupIds {
		scopeId, groupId, err := scopeAndIdForRole(role.ScopeId, id)
		if err != nil {
			return 0, err
		}
		grpRole, err := NewGroupRole(scopeId, roleId, groupId)
		if err != nil {
			return db.NoRowsAffected, fmt.Errorf("delete principal roles: unable to create in memory group role: %w", err)
		}
		deleteGrpRoles = append(deleteGrpRoles, grpRole)
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
				return fmt.Errorf("delete principal roles: unable to get ticket: %w", err)
			}
			updatedRole := allocRole()
			updatedRole.PublicId = roleId
			updatedRole.Version = uint32(roleVersion) + 1
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(roleVersion))
			if err != nil {
				return fmt.Errorf("delete principal roles: unable to update role version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("delete principal roles: updated role and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &roleOplogMsg)
			if len(deleteUserRoles) > 0 {
				userOplogMsgs := make([]*oplog.Message, 0, len(deleteUserRoles))
				rowsDeleted, err := w.DeleteItems(ctx, deleteUserRoles, db.NewOplogMsgs(&userOplogMsgs))
				if err != nil {
					return fmt.Errorf("delete principal roles: unable to delete user roles: %w", err)
				}
				if rowsDeleted != len(deleteUserRoles) {
					return fmt.Errorf("delete principal roles: user roles deleted %d did not match request for %d", rowsDeleted, len(deleteUserRoles))
				}
				totalRowsDeleted += rowsDeleted
				msgs = append(msgs, userOplogMsgs...)
			}
			if len(deleteGrpRoles) > 0 {
				grpOplogMsgs := make([]*oplog.Message, 0, len(deleteGrpRoles))
				rowsDeleted, err := w.DeleteItems(ctx, deleteGrpRoles, db.NewOplogMsgs(&grpOplogMsgs))
				if err != nil {
					return fmt.Errorf("delete principal roles: unable to delete groups: %w", err)
				}
				if rowsDeleted != len(deleteGrpRoles) {
					return fmt.Errorf("delete principal roles: group roles deleted %d did not match request for %d", rowsDeleted, len(deleteGrpRoles))
				}
				totalRowsDeleted += rowsDeleted
				msgs = append(msgs, grpOplogMsgs...)
			}
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_DELETE.String()},
				"scope-id":           []string{scope.PublicId},
				"scope-type":         []string{scope.Type},
				"resource-public-id": []string{roleId},
			}
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, roleTicket, metadata, msgs); err != nil {
				return fmt.Errorf("delete principal roles: unable to write oplog: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete principal roles: error deleting principal roles: %w", err)
	}
	return totalRowsDeleted, nil
}

// ListPrincipalRoles returns the principal roles for the roleId and supports the WithLimit option.
func (r *Repository) ListPrincipalRoles(ctx context.Context, roleId string, opt ...Option) ([]PrincipalRole, error) {
	if roleId == "" {
		return nil, fmt.Errorf("lookup principal roles: missing role id: %w", db.ErrInvalidParameter)
	}
	var roles []principalRoleView
	if err := r.list(ctx, &roles, "role_id = ?", []interface{}{roleId}, opt...); err != nil {
		return nil, fmt.Errorf("lookup principal role: unable to lookup roles: %w", err)
	}
	principals := make([]PrincipalRole, 0, len(roles))
	for _, r := range roles {
		principals = append(principals, r)
	}
	return principals, nil
}

type principalSet struct {
	addUserRoles     []interface{}
	addGroupRoles    []interface{}
	deleteUserRoles  []interface{}
	deleteGroupRoles []interface{}
	// unchangedPrincipalRoles is set iff there are no changes, that is, the
	// length of all other members is zero
	unchangedPrincipalRoles []PrincipalRole
}

// TODO: Should this be moved inside the transaction, at this point?
func (r *Repository) principalsToSet(ctx context.Context, role *Role, userIds, groupIds []string) (*principalSet, error) {
	if role == nil {
		return nil, fmt.Errorf("missing role: %w", db.ErrNilParameter)
	}
	existing, err := r.ListPrincipalRoles(ctx, role.PublicId)
	if err != nil {
		return nil, fmt.Errorf("unable to list existing principal role %s: %w", role.PublicId, err)
	}
	existingUsers := map[string]PrincipalRole{}
	existingGroups := map[string]PrincipalRole{}
	for _, p := range existing {
		scopedPrincipalId, err := p.GetScopedPrincipalId(ctx, r.reader)
		if err != nil {
			return nil, fmt.Errorf("unable to look up scoped principal id for %s in role %s: %w", p.GetPrincipalId(), role.PublicId, err)
		}
		switch p.GetType() {
		case UserRoleType.String():
			existingUsers[scopedPrincipalId] = p
		case GroupRoleType.String():
			existingGroups[scopedPrincipalId] = p
		default:
			return nil, fmt.Errorf("%s is unknown principal type %s", scopedPrincipalId, p.GetType())
		}
	}
	var newUserRoles []interface{}
	userIdsMap := map[string]struct{}{}
	for _, id := range userIds {
		userIdsMap[id] = struct{}{}
		if _, ok := existingUsers[id]; !ok {
			usrRole, err := NewUserRole(role.ScopeId, role.PublicId, id)
			if err != nil {
				return nil, fmt.Errorf("unable to create in memory user role for add: %w", err)
			}
			newUserRoles = append(newUserRoles, usrRole)
		}
	}
	var newGrpRoles []interface{}
	groupIdsMap := map[string]struct{}{}
	for _, id := range groupIds {
		groupIdsMap[id] = struct{}{}
		if _, ok := existingGroups[id]; !ok {
			grpRole, err := NewGroupRole(role.ScopeId, role.PublicId, id)
			if err != nil {
				return nil, fmt.Errorf("unable to create in memory group role for add: %w", err)
			}
			newGrpRoles = append(newGrpRoles, grpRole)
		}
	}
	var deleteUserRoles []interface{}
	for _, p := range existingUsers {
		scopedPrincipalId, err := p.GetScopedPrincipalId(ctx, r.reader)
		if err != nil {
			return nil, fmt.Errorf("unable to look up scoped principal id for %s in role %s: %w", p.GetPrincipalId(), role.PublicId, err)
		}
		if _, ok := userIdsMap[scopedPrincipalId]; !ok {
			usrRole, err := NewUserRole(p.GetScopeId(), p.GetRoleId(), p.GetPrincipalId())
			if err != nil {
				return nil, fmt.Errorf("unable to create in memory user role for delete: %w", err)
			}
			deleteUserRoles = append(deleteUserRoles, usrRole)
		}
	}
	var deleteGrpRoles []interface{}
	for _, p := range existingGroups {
		scopedPrincipalId, err := p.GetScopedPrincipalId(ctx, r.reader)
		if err != nil {
			return nil, fmt.Errorf("unable to look up scoped principal id for %s in role %s: %w", p.GetPrincipalId(), role.PublicId, err)
		}
		if _, ok := groupIdsMap[scopedPrincipalId]; !ok {
			grpRole, err := NewGroupRole(p.GetScopeId(), p.GetRoleId(), p.GetPrincipalId())
			if err != nil {
				return nil, fmt.Errorf("unable to create in memory group role for delete: %w", err)
			}
			deleteGrpRoles = append(deleteGrpRoles, grpRole)
		}
	}

	toSet := &principalSet{
		addUserRoles:     newUserRoles,
		addGroupRoles:    newGrpRoles,
		deleteUserRoles:  deleteUserRoles,
		deleteGroupRoles: deleteGrpRoles,
	}

	if len(toSet.addUserRoles) == 0 && len(toSet.addGroupRoles) == 0 && len(toSet.deleteUserRoles) == 0 && len(toSet.deleteGroupRoles) == 0 {
		toSet.unchangedPrincipalRoles = existing
	}

	return toSet, nil
}
