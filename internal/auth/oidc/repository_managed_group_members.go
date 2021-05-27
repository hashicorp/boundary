package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// setManagedGroups will set the managed groups for the given account ID. If mgs
// is empty, the set of groups the account belongs to will be cleared. It
// returns the set of managed group IDs.
//
// mgs contains the set of managed groups that matched. It must contain the
// group's version as this is used to ensure consistency.
func (r *Repository) setManagedGroupMembers(ctx context.Context, am *AuthMethod, acct *Account, mgs []*ManagedGroup, _ ...Option) ([]string, int, error) {
	const op = "oidc.(Repository).setManagedGroupMembers"
	if am == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if am.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	if am.ScopeId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method scope id")
	}
	if acct == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing account")
	}
	if acct.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing account id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	newMgPublicIds := make(map[string]bool, len(mgs))
	updatedMgs := make([]*ManagedGroup, 0, len(mgs))
	for _, mg := range mgs {
		if mg.Version == 0 {
			return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("missing version for managed group %s", mg.PublicId))
		}
		updatedMg := AllocManagedGroup()
		updatedMg.PublicId = mg.PublicId
		updatedMg.Version = mg.Version + 1
		updatedMgs = append(updatedMgs, updatedMg)
		newMgPublicIds[mg.PublicId] = true
	}

	ticketMg := AllocManagedGroup()
	var totalRowsAffected int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			// We need a ticket, which won't be redeemed until all the other
			// writes are successful. We can't just use a single ticket because
			// we need to write oplog entries for deletes and adds.
			mgTicket, err := w.GetTicket(ticketMg)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket for oidc managed groups"))
			}

			msgs := make([]*oplog.Message, 0, len(mgs)+5)
			metadata := oplog.Metadata{
				"op-type":        []string{oplog.OpType_OP_TYPE_UPDATE.String()},
				"scope-id":       []string{am.ScopeId},
				"auth-method-id": []string{am.PublicId},
				"account-id":     []string{acct.PublicId},
			}

			// Ensure that none of the filters have changed or will change
			// during this operation
			for i, updatedMg := range updatedMgs {
				var mgOplogMsg oplog.Message
				rowsUpdated, err := w.Update(ctx, updatedMg, []string{"Version"}, nil, db.NewOplogMsg(&mgOplogMsg), db.WithVersion(&mgs[i].Version))
				if err != nil {
					return errors.Wrap(err, op)
				}
				if rowsUpdated != 1 {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated oidc managed group and %d rows updated", rowsUpdated))
				}
				msgs = append(msgs, &mgOplogMsg)
			}

			// Find all existing memberships
			rows, err := reader.Query(ctx, findManagedGroupMembershipsForAccount, []interface{}{acct.PublicId})
			if err != nil {
				return errors.Wrap(err, op)
			}

			toDelete := make([]interface{}, 0, len(mgs))
			var currMgId string
			for rows.Next() {
				if err := rows.Scan(&currMgId); err != nil {
					return errors.Wrap(err, op)
				}
				if newMgPublicIds[currMgId] {
					// We're slated to add it in, but it's already in there, so
					// take it out of the new list
					delete(newMgPublicIds, currMgId)
				} else {
					// It's not currently matching a filter, so needs to be deleted
					delMg := AllocManagedGroupMemberAccount()
					delMg.ManagedGroupId = currMgId
					delMg.MemberId = acct.PublicId
					toDelete = append(toDelete, delMg)
				}
			}

			// At this point, anything in toDelete should be deleted, and
			// anything left in newMgPublicIds should be added

			// Start with deletion
			if len(toDelete) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
				deleteOplogMsgs := make([]*oplog.Message, 0, len(toDelete))
				rowsDeleted, err := w.DeleteItems(ctx, toDelete, db.NewOplogMsgs(&deleteOplogMsgs))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to delete managed group member accounts"))
				}
				if rowsDeleted != len(toDelete) {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("managed group member accounts deleted %d did not match request for %d", rowsDeleted, len(toDelete)))
				}
				totalRowsAffected += rowsDeleted
				msgs = append(msgs, deleteOplogMsgs...)
			}

			// Now do insertion
			if len(toSet.addUserRoles) > 0 || len(toSet.addGroupRoles) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
				if len(toSet.addUserRoles) > 0 {
					userOplogMsgs := make([]*oplog.Message, 0, len(toSet.addUserRoles))
					if err := w.CreateItems(ctx, toSet.addUserRoles, db.NewOplogMsgs(&userOplogMsgs)); err != nil {
						return errors.Wrap(err, op, errors.WithMsg("unable to add users"))
					}
					totalRowsAffected += len(toSet.addUserRoles)
					msgs = append(msgs, userOplogMsgs...)
				}
				if len(toSet.addGroupRoles) > 0 {
					grpOplogMsgs := make([]*oplog.Message, 0, len(toSet.addGroupRoles))
					if err := w.CreateItems(ctx, toSet.addGroupRoles, db.NewOplogMsgs(&grpOplogMsgs)); err != nil {
						return errors.Wrap(err, op, errors.WithMsg("unable to add groups"))
					}
					totalRowsAffected += len(toSet.addGroupRoles)
					msgs = append(msgs, grpOplogMsgs...)
				}
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, mgTicket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
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
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current principal roles after sets"))
			}
			return nil
		})
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	return currentPrincipals, totalRowsAffected, nil
}

type managedGroupSet struct {
	addMgs                  []interface{}
	deleteMgsRoles          []interface{}
	unchangedPrincipalRoles []PrincipalRole
}

func (r *Repository) managedGroupssToSet(ctx context.Context, role *Role, userIds, groupIds []string) (*principalSet, error) {
	const op = "iam.(Repository).principalsToSet"
	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.
	if role == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing role")
	}
	existing, err := r.ListPrincipalRoles(ctx, role.PublicId)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to list existing principal role %s", role.PublicId)))
	}
	existingUsers := map[string]PrincipalRole{}
	existingGroups := map[string]PrincipalRole{}
	for _, p := range existing {
		switch p.GetType() {
		case UserRoleType.String():
			existingUsers[p.PrincipalId] = p
		case GroupRoleType.String():
			existingGroups[p.PrincipalId] = p
		default:
			return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is unknown principal type %s", p.PrincipalId, p.GetType()))
		}
	}
	var newUserRoles []interface{}
	userIdsMap := map[string]struct{}{}
	for _, id := range userIds {
		userIdsMap[id] = struct{}{}
		if _, ok := existingUsers[id]; !ok {
			usrRole, err := NewUserRole(role.PublicId, id)
			if err != nil {
				return nil, errors.Wrap(err, op, errors.WithMsg("unable to create in memory user role for add"))
			}
			newUserRoles = append(newUserRoles, usrRole)
		}
	}
	var newGrpRoles []interface{}
	groupIdsMap := map[string]struct{}{}
	for _, id := range groupIds {
		groupIdsMap[id] = struct{}{}
		if _, ok := existingGroups[id]; !ok {
			grpRole, err := NewGroupRole(role.PublicId, id)
			if err != nil {
				return nil, errors.Wrap(err, op, errors.WithMsg("unable to create in memory group role for add"))
			}
			newGrpRoles = append(newGrpRoles, grpRole)
		}
	}
	var deleteUserRoles []interface{}
	for _, p := range existingUsers {
		if _, ok := userIdsMap[p.PrincipalId]; !ok {
			usrRole, err := NewUserRole(p.GetRoleId(), p.GetPrincipalId())
			if err != nil {
				return nil, errors.Wrap(err, op, errors.WithMsg("unable to create in memory user role for delete"))
			}
			deleteUserRoles = append(deleteUserRoles, usrRole)
		}
	}
	var deleteGrpRoles []interface{}
	for _, p := range existingGroups {
		if _, ok := groupIdsMap[p.PrincipalId]; !ok {
			grpRole, err := NewGroupRole(p.GetRoleId(), p.GetPrincipalId())
			if err != nil {
				return nil, errors.Wrap(err, op, errors.WithMsg("unable to create in memory group role for delete"))
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

func splitPrincipals(principals []string) ([]string, []string, error) {
	const op = "iam.splitPrincipals"
	var users, groups []string
	for _, principal := range principals {
		switch {
		case strings.HasPrefix(principal, UserPrefix):
			users = append(users, principal)
		// TODO: This needs to handle all of the kinds of group prefixes (sg_, dg_, etc.)
		case strings.HasPrefix(principal, GroupPrefix):
			groups = append(groups, principal)
		default:
			return nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("invalid principal ID %q", principal))
		}
	}

	return users, groups, nil
}
