package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// AddPrincipalRoles provides the ability to add principals (userIds and
// groupIds) to a role (roleId).  The role's current db version must match the
// roleVersion or an error will be returned.  The role, users and groups must
// all be in the same scope
func (r *Repository) AddPrincipalRoles(ctx context.Context, roleId string, roleVersion int, userIds, groupIds []string, opt ...Option) ([]PrincipalRole, error) {
	// NOTE - we are intentionally not going to check that the scopes are
	// correct for the userIds and groupIds, given the roleId.  We are going to
	// rely on the database constraints and triggers to maintain the integrity
	// of these scope relationships.  The users and role need to either be in
	// the same organization or the role needs to be in a project of the user's
	// org.  The groups and role have to be in the same scope (org or project).
	// There are constraints and triggers to enforce these relationships.
	if roleId == "" {
		return nil, fmt.Errorf("add principal roles: missing role id %w", db.ErrInvalidParameter)
	}
	if len(userIds) == 0 && len(groupIds) == 0 {
		return nil, fmt.Errorf("add principal roles: missing either user or groups to add %w", db.ErrInvalidParameter)
	}
	role := allocRole()
	role.PublicId = roleId
	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("add principal roles: unable to get role %s scope to create metadata: %w", roleId, err)
	}
	metadata := oplog.Metadata{
		"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
		"scope-id":           []string{scope.PublicId},
		"scope-type":         []string{scope.Type},
		"resource-public-id": []string{roleId},
	}
	newUserRoles := make([]interface{}, 0, len(userIds))
	for _, id := range userIds {
		usrRole, err := NewUserRole(scope.PublicId, roleId, id)
		if err != nil {
			return nil, fmt.Errorf("add principal roles: unable to create new in memory user role: %w", err)
		}
		newUserRoles = append(newUserRoles, usrRole)
	}
	newGrpRoles := make([]interface{}, 0, len(groupIds))
	for _, id := range groupIds {
		grpRole, err := NewGroupRole(scope.PublicId, roleId, id)
		if err != nil {
			return nil, fmt.Errorf("add principal roles: unable to create new in memory group role: %w", err)
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
			if err := w.WriteOplogEntryWith(ctx, r.wrapper, roleTicket, metadata, msgs); err != nil {
				return fmt.Errorf("add principal roles: unable to write oplog: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
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

func (r *Repository) SetPrincipalRoles(ctx context.Context, roleId string, userIds, groupIds []string, opt ...Option) ([]*PrincipalRole, int, error) {
	panic("not implemented")
}

// ListPrincipalRoles returns the principal roles for the roleId and supports the WithLimit option.
func (r *Repository) ListPrincipalRoles(ctx context.Context, roleId string, opt ...Option) ([]PrincipalRole, error) {
	if roleId == "" {
		return nil, fmt.Errorf("lookup principal roles: missing role id %w", db.ErrInvalidParameter)
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
func (r *Repository) DeletePrincipalRoles(ctx context.Context, roleId string, userIds, groupIds []string, opt ...Option) (int, error) {
	panic("not implemented")
}
