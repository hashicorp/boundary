// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// AddPrincipalRoles provides the ability to add principals (userIds and
// groupIds) to a role (roleId).  The role's current db version must match the
// roleVersion or an error will be returned.  The list of current PrincipalRoles
// after the adds will be returned on success. Zero is not a valid value for
// the WithVersion option and will return an error.
func (r *Repository) AddPrincipalRoles(ctx context.Context, roleId string, roleVersion uint32, principalIds []string, _ ...Option) ([]*PrincipalRole, error) {
	const op = "iam.(Repository).AddPrincipalRoles"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if roleVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	userIds, groupIds, managedGroupIds, err := splitPrincipals(ctx, principalIds)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(userIds) == 0 && len(groupIds) == 0 && len(managedGroupIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing any of users, groups, or managed groups to add")
	}
	newUserRoles := make([]*UserRole, 0, len(userIds))
	for _, id := range userIds {
		usrRole, err := NewUserRole(ctx, roleId, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory user role"))
		}
		newUserRoles = append(newUserRoles, usrRole)
	}
	newGrpRoles := make([]*GroupRole, 0, len(groupIds))
	for _, id := range groupIds {
		grpRole, err := NewGroupRole(ctx, roleId, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory group role"))
		}
		newGrpRoles = append(newGrpRoles, grpRole)
	}
	newManagedGrpRoles := make([]*ManagedGroupRole, 0, len(managedGroupIds))
	for _, id := range managedGroupIds {
		managedGrpRole, err := NewManagedGroupRole(ctx, roleId, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory managed group role"))
		}
		newManagedGrpRoles = append(newManagedGrpRoles, managedGrpRole)
	}
	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope", roleId)))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var currentPrincipals []*PrincipalRole
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
			if len(newUserRoles) > 0 {
				userOplogMsgs := make([]*oplog.Message, 0, len(newUserRoles))
				if err := w.CreateItems(ctx, newUserRoles, db.NewOplogMsgs(&userOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add users"))
				}
				msgs = append(msgs, userOplogMsgs...)
			}
			if len(newGrpRoles) > 0 {
				grpOplogMsgs := make([]*oplog.Message, 0, len(newGrpRoles))
				if err := w.CreateItems(ctx, newGrpRoles, db.NewOplogMsgs(&grpOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add groups"))
				}
				msgs = append(msgs, grpOplogMsgs...)
			}
			if len(newManagedGrpRoles) > 0 {
				managedGrpOplogMsgs := make([]*oplog.Message, 0, len(newManagedGrpRoles))
				if err := w.CreateItems(ctx, newManagedGrpRoles, db.NewOplogMsgs(&managedGrpOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add managed groups"))
				}
				msgs = append(msgs, managedGrpOplogMsgs...)
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
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the principal roles without a limit
			}
			currentPrincipals, err = txRepo.ListPrincipalRoles(ctx, roleId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current principal roles after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return currentPrincipals, nil
}

// SetPrincipalRoles will set the role's principals. Set add and/or delete
// principals as need to reconcile the existing principals with the principals
// requested. If both userIds and groupIds are empty, the principal roles will
// be cleared. Zero is not a valid value for the WithVersion option and will
// return an error.
func (r *Repository) SetPrincipalRoles(ctx context.Context, roleId string, roleVersion uint32, principalIds []string, _ ...Option) ([]*PrincipalRole, int, error) {
	const op = "iam.(Repository).SetPrincipalRoles"
	if roleId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	if roleVersion == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	// it's "safe" to do this lookup outside the DoTx transaction because we
	// have a roleVersion so the principals can’t change without the version
	// changing.
	userIds, groupIds, managedGroupIds, err := splitPrincipals(ctx, principalIds)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	toSet, err := r.PrincipalsToSet(ctx, &Role{PublicId: roleId}, userIds, groupIds, managedGroupIds)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	// handle no change to existing principal roles
	if len(toSet.UnchangedPrincipalRoles) > 0 {
		return toSet.UnchangedPrincipalRoles, db.NoRowsAffected, nil
	}

	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope", roleId)))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scp.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var currentPrincipals []*PrincipalRole
	var totalRowsAffected int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			// we need a roleTicket, which won't be redeemed until all the other
			// writes are successful.  We can't just use a single ticket because
			// we need to write oplog entries for deletes and adds
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
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket for role"))
			}
			var roleOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedRole, []string{"Version"}, nil, db.NewOplogMsg(&roleOplogMsg), db.WithVersion(&roleVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated role and %d rows updated", rowsUpdated))
			}
			msgs := make([]*oplog.Message, 0, 5)
			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":           []string{scp.PublicId},
				"scope-type":         []string{scp.Type},
				"resource-public-id": []string{roleId},
			}
			msgs = append(msgs, &roleOplogMsg)

			if len(toSet.DeleteUserRoles) > 0 ||
				len(toSet.DeleteGroupRoles) > 0 ||
				len(toSet.DeleteManagedGroupRoles) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
				if len(toSet.DeleteUserRoles) > 0 {
					userOplogMsgs := make([]*oplog.Message, 0, len(toSet.DeleteUserRoles))
					rowsDeleted, err := w.DeleteItems(ctx, toSet.DeleteUserRoles, db.NewOplogMsgs(&userOplogMsgs))
					if err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete user roles"))
					}
					if rowsDeleted != len(toSet.DeleteUserRoles) {
						return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("user roles deleted %d did not match request for %d", rowsDeleted, len(toSet.DeleteUserRoles)))
					}
					totalRowsAffected += rowsDeleted
					msgs = append(msgs, userOplogMsgs...)
				}
				if len(toSet.DeleteGroupRoles) > 0 {
					grpOplogMsgs := make([]*oplog.Message, 0, len(toSet.DeleteGroupRoles))
					rowsDeleted, err := w.DeleteItems(ctx, toSet.DeleteGroupRoles, db.NewOplogMsgs(&grpOplogMsgs))
					if err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete groups"))
					}
					if rowsDeleted != len(toSet.DeleteGroupRoles) {
						return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("group roles deleted %d did not match request for %d", rowsDeleted, len(toSet.DeleteGroupRoles)))
					}
					totalRowsAffected += rowsDeleted
					msgs = append(msgs, grpOplogMsgs...)
				}
				if len(toSet.DeleteManagedGroupRoles) > 0 {
					managedGrpOplogMsgs := make([]*oplog.Message, 0, len(toSet.DeleteManagedGroupRoles))
					rowsDeleted, err := w.DeleteItems(ctx, toSet.DeleteManagedGroupRoles, db.NewOplogMsgs(&managedGrpOplogMsgs))
					if err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete managed groups"))
					}
					if rowsDeleted != len(toSet.DeleteManagedGroupRoles) {
						return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("managed group roles deleted %d did not match request for %d", rowsDeleted, len(toSet.DeleteManagedGroupRoles)))
					}
					totalRowsAffected += rowsDeleted
					msgs = append(msgs, managedGrpOplogMsgs...)
				}
			}
			if len(toSet.AddUserRoles) > 0 ||
				len(toSet.AddGroupRoles) > 0 ||
				len(toSet.AddManagedGroupRoles) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
				if len(toSet.AddUserRoles) > 0 {
					userOplogMsgs := make([]*oplog.Message, 0, len(toSet.AddUserRoles))
					if err := w.CreateItems(ctx, toSet.AddUserRoles, db.NewOplogMsgs(&userOplogMsgs)); err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add users"))
					}
					totalRowsAffected += len(toSet.AddUserRoles)
					msgs = append(msgs, userOplogMsgs...)
				}
				if len(toSet.AddGroupRoles) > 0 {
					grpOplogMsgs := make([]*oplog.Message, 0, len(toSet.AddGroupRoles))
					if err := w.CreateItems(ctx, toSet.AddGroupRoles, db.NewOplogMsgs(&grpOplogMsgs)); err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add groups"))
					}
					totalRowsAffected += len(toSet.AddGroupRoles)
					msgs = append(msgs, grpOplogMsgs...)
				}
				if len(toSet.AddManagedGroupRoles) > 0 {
					managedGrpOplogMsgs := make([]*oplog.Message, 0, len(toSet.AddManagedGroupRoles))
					if err := w.CreateItems(ctx, toSet.AddManagedGroupRoles, db.NewOplogMsgs(&managedGrpOplogMsgs)); err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add managed groups"))
					}
					totalRowsAffected += len(toSet.AddManagedGroupRoles)
					msgs = append(msgs, managedGrpOplogMsgs...)
				}
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, roleTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the principal roles without a limit
			}
			currentPrincipals, err = txRepo.ListPrincipalRoles(ctx, roleId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current principal roles after sets"))
			}
			return nil
		})
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return currentPrincipals, totalRowsAffected, nil
}

// DeletePrincipalRoles principals (userIds and/or groupIds) from a role
// (roleId). The role's current db version must match the roleVersion or an
// error will be returned. Zero is not a valid value for the WithVersion option
// and will return an error.
func (r *Repository) DeletePrincipalRoles(ctx context.Context, roleId string, roleVersion uint32, principalIds []string, _ ...Option) (int, error) {
	const op = "iam.(Repository).DeletePrincipalRoles"
	if roleId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	userIds, groupIds, managedGroupIds, err := splitPrincipals(ctx, principalIds)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if len(userIds) == 0 && len(groupIds) == 0 && len(managedGroupIds) == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing any of users, groups, or managed groups to delete")
	}
	if roleVersion == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	var roleResource Resource
	scp, err := getRoleScope(ctx, r.reader, roleId)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to get role %s scope", roleId)))
	}
	deleteUserRoles := make([]*UserRole, 0, len(userIds))
	for _, id := range userIds {
		usrRole, err := NewUserRole(ctx, roleId, id)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory user role"))
		}
		deleteUserRoles = append(deleteUserRoles, usrRole)
	}
	deleteGrpRoles := make([]*GroupRole, 0, len(groupIds))
	for _, id := range groupIds {
		grpRole, err := NewGroupRole(ctx, roleId, id)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory group role"))
		}
		deleteGrpRoles = append(deleteGrpRoles, grpRole)
	}
	deleteManagedGrpRoles := make([]*ManagedGroupRole, 0, len(managedGroupIds))
	for _, id := range managedGroupIds {
		managedGrpRole, err := NewManagedGroupRole(ctx, roleId, id)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory managed group role"))
		}
		deleteManagedGrpRoles = append(deleteManagedGrpRoles, managedGrpRole)
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
			switch scp.Type {
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
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown role resource type %T", roleResource))
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
			if len(deleteUserRoles) > 0 {
				userOplogMsgs := make([]*oplog.Message, 0, len(deleteUserRoles))
				rowsDeleted, err := w.DeleteItems(ctx, deleteUserRoles, db.NewOplogMsgs(&userOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete user roles"))
				}
				if rowsDeleted != len(deleteUserRoles) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("user roles deleted %d did not match request for %d", rowsDeleted, len(deleteUserRoles)))
				}
				totalRowsDeleted += rowsDeleted
				msgs = append(msgs, userOplogMsgs...)
			}
			if len(deleteGrpRoles) > 0 {
				grpOplogMsgs := make([]*oplog.Message, 0, len(deleteGrpRoles))
				rowsDeleted, err := w.DeleteItems(ctx, deleteGrpRoles, db.NewOplogMsgs(&grpOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete groups"))
				}
				if rowsDeleted != len(deleteGrpRoles) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("group roles deleted %d did not match request for %d", rowsDeleted, len(deleteGrpRoles)))
				}
				totalRowsDeleted += rowsDeleted
				msgs = append(msgs, grpOplogMsgs...)
			}
			if len(deleteManagedGrpRoles) > 0 {
				managedGrpOplogMsgs := make([]*oplog.Message, 0, len(deleteManagedGrpRoles))
				rowsDeleted, err := w.DeleteItems(ctx, deleteManagedGrpRoles, db.NewOplogMsgs(&managedGrpOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete managed groups"))
				}
				if rowsDeleted != len(deleteManagedGrpRoles) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("managed group roles deleted %d did not match request for %d", rowsDeleted, len(deleteManagedGrpRoles)))
				}
				totalRowsDeleted += rowsDeleted
				msgs = append(msgs, managedGrpOplogMsgs...)
			}
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

// ListPrincipalRoles returns the principal roles for the roleId and supports the WithLimit option.
func (r *Repository) ListPrincipalRoles(ctx context.Context, roleId string, opt ...Option) ([]*PrincipalRole, error) {
	const op = "iam.(Repository).ListPrincipalRoles"
	if roleId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role id")
	}
	var roles []*PrincipalRole
	if err := r.list(ctx, &roles, "role_id = ?", []any{roleId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup roles"))
	}
	principals := make([]*PrincipalRole, 0, len(roles))
	principals = append(principals, roles...)
	return principals, nil
}

type PrincipalSet struct {
	AddUserRoles            []*UserRole
	AddGroupRoles           []*GroupRole
	AddManagedGroupRoles    []*ManagedGroupRole
	DeleteUserRoles         []*UserRole
	DeleteGroupRoles        []*GroupRole
	DeleteManagedGroupRoles []*ManagedGroupRole
	// unchangedPrincipalRoles is set iff there are no changes, that is, the
	// length of all other members is zero
	UnchangedPrincipalRoles []*PrincipalRole
}

// TODO: Should this be moved inside the transaction, at this point?
// PrincipalsToSet sets principals on a role from the given lists.
func (r *Repository) PrincipalsToSet(ctx context.Context, role *Role, userIds, groupIds, managedGroupIds []string) (*PrincipalSet, error) {
	const op = "iam.(Repository).PrincipalsToSet"
	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.
	if role == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing role")
	}
	existing, err := r.ListPrincipalRoles(ctx, role.PublicId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to list existing principal role %s", role.PublicId)))
	}
	existingUsers := map[string]*PrincipalRole{}
	existingGroups := map[string]*PrincipalRole{}
	existingManagedGroups := map[string]*PrincipalRole{}
	for _, p := range existing {
		switch p.GetType() {
		case UserRoleType.String():
			existingUsers[p.PrincipalId] = p
		case GroupRoleType.String():
			existingGroups[p.PrincipalId] = p
		case ManagedGroupRoleType.String():
			existingManagedGroups[p.PrincipalId] = p
		default:
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is unknown principal type %s", p.PrincipalId, p.GetType()))
		}
	}
	var newUserRoles []*UserRole
	userIdsMap := map[string]struct{}{}
	for _, id := range userIds {
		userIdsMap[id] = struct{}{}
		if _, ok := existingUsers[id]; !ok {
			usrRole, err := NewUserRole(ctx, role.PublicId, id)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory user role for add"))
			}
			newUserRoles = append(newUserRoles, usrRole)
		}
	}
	var newGrpRoles []*GroupRole
	groupIdsMap := map[string]struct{}{}
	for _, id := range groupIds {
		groupIdsMap[id] = struct{}{}
		if _, ok := existingGroups[id]; !ok {
			grpRole, err := NewGroupRole(ctx, role.PublicId, id)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory group role for add"))
			}
			newGrpRoles = append(newGrpRoles, grpRole)
		}
	}
	var newManagedGrpRoles []*ManagedGroupRole
	managedGroupIdsMap := map[string]struct{}{}
	for _, id := range managedGroupIds {
		managedGroupIdsMap[id] = struct{}{}
		if _, ok := existingManagedGroups[id]; !ok {
			managedGrpRole, err := NewManagedGroupRole(ctx, role.PublicId, id)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory managed group role for add"))
			}
			newManagedGrpRoles = append(newManagedGrpRoles, managedGrpRole)
		}
	}
	var deleteUserRoles []*UserRole
	for _, p := range existingUsers {
		if _, ok := userIdsMap[p.PrincipalId]; !ok {
			usrRole, err := NewUserRole(ctx, p.GetRoleId(), p.GetPrincipalId())
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory user role for delete"))
			}
			deleteUserRoles = append(deleteUserRoles, usrRole)
		}
	}
	var deleteGrpRoles []*GroupRole
	for _, p := range existingGroups {
		if _, ok := groupIdsMap[p.PrincipalId]; !ok {
			grpRole, err := NewGroupRole(ctx, p.GetRoleId(), p.GetPrincipalId())
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory group role for delete"))
			}
			deleteGrpRoles = append(deleteGrpRoles, grpRole)
		}
	}
	var deleteManagedGrpRoles []*ManagedGroupRole
	for _, p := range existingManagedGroups {
		if _, ok := managedGroupIdsMap[p.PrincipalId]; !ok {
			managedGrpRole, err := NewManagedGroupRole(ctx, p.GetRoleId(), p.GetPrincipalId())
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory managed group role for delete"))
			}
			deleteManagedGrpRoles = append(deleteManagedGrpRoles, managedGrpRole)
		}
	}

	toSet := &PrincipalSet{
		AddUserRoles:            newUserRoles,
		AddGroupRoles:           newGrpRoles,
		AddManagedGroupRoles:    newManagedGrpRoles,
		DeleteUserRoles:         deleteUserRoles,
		DeleteGroupRoles:        deleteGrpRoles,
		DeleteManagedGroupRoles: deleteManagedGrpRoles,
	}

	if len(toSet.AddUserRoles) == 0 &&
		len(toSet.AddGroupRoles) == 0 &&
		len(toSet.AddManagedGroupRoles) == 0 &&
		len(toSet.DeleteUserRoles) == 0 &&
		len(toSet.DeleteGroupRoles) == 0 &&
		len(toSet.DeleteManagedGroupRoles) == 0 {
		toSet.UnchangedPrincipalRoles = existing
	}

	return toSet, nil
}

func splitPrincipals(ctx context.Context, principals []string) (users, groups, managedGroups []string, retErr error) {
	const op = "iam.splitPrincipals"
	for _, principal := range principals {
		switch {
		case strings.HasPrefix(principal, globals.UserPrefix):
			if users == nil {
				users = make([]string, 0, len(principals))
			}
			users = append(users, principal)
		case strings.HasPrefix(principal, globals.GroupPrefix):
			if groups == nil {
				groups = make([]string, 0, len(principals))
			}
			groups = append(groups, principal)
		case strings.HasPrefix(principal, globals.OidcManagedGroupPrefix):
			if managedGroups == nil {
				managedGroups = make([]string, 0, len(principals))
			}
			managedGroups = append(managedGroups, principal)
		case strings.HasPrefix(principal, globals.LdapManagedGroupPrefix):
			if managedGroups == nil {
				managedGroups = make([]string, 0, len(principals))
			}
			managedGroups = append(managedGroups, principal)
		default:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid principal ID %q", principal))
		}
	}

	return users, groups, managedGroups, retErr
}
