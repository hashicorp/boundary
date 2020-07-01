package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// AddRoleGrant will add a role grant associated with the role ID in the
// repository. No options are currently supported.
func (r *Repository) AddRoleGrants(ctx context.Context, roleId string, roleVersion int, grants []string, opt ...Option) ([]*RoleGrant, error) {
	if roleId == "" {
		return nil, fmt.Errorf("add role grants: missing role id %w", db.ErrInvalidParameter)
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf("add role grants: missing grants: %w", db.ErrInvalidParameter)
	}
	role := allocRole()
	role.PublicId = roleId
	scope, err := role.GetScope(ctx, r.reader)
	if err != nil {
		return nil, fmt.Errorf("add role grants: unable to get role %s scope to create metadata: %w", roleId, err)
	}
	metadata := oplog.Metadata{
		"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
		"scope-id":           []string{scope.PublicId},
		"scope-type":         []string{scope.Type},
		"resource-public-id": []string{roleId},
	}

	newRoleGrants := make([]interface{}, 0, len(grants))
	for _, grant := range grants {
		roleGrant, err := NewRoleGrant(roleId, grant)
		if err != nil {
			return nil, fmt.Errorf("add role grants: unable to create in memory role grant: %w", err)
		}
		roleGrant.PrivateId, err = newRoleGrantId()
		if err != nil {
			return nil, fmt.Errorf("add role grants: unable to generate new id: %w", err)
		}
		newRoleGrants = append(newRoleGrants, roleGrant)
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
			rowsUpdated, err := w.Update(ctx, &updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(roleVersion))
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
