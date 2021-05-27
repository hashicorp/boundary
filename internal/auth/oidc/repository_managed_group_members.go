package oidc

import (
	"context"
	"fmt"

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
func (r *Repository) SetManagedGroupMembers(ctx context.Context, am *AuthMethod, acct *Account, mgs []*ManagedGroup, _ ...Option) (int, error) {
	const op = "oidc.(Repository).setManagedGroupMembers"
	if am == nil {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if am.AuthMethod == nil {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method store")
	}
	if am.PublicId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	if am.ScopeId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method scope id")
	}
	if acct == nil {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing account")
	}
	if acct.Account == nil {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing account store")
	}
	if acct.PublicId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing account id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	newMgPublicIds := make(map[string]bool, len(mgs))
	updatedMgs := make([]*ManagedGroup, 0, len(mgs))
	for _, mg := range mgs {
		if mg.Version == 0 {
			return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("missing version for managed group %s", mg.PublicId))
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

			// Figure out which ones to delete and which ones we already have
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
			if len(newMgPublicIds) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
				addOplogMsgs := make([]*oplog.Message, 0, len(newMgPublicIds))
				toAdd := make([]interface{}, 0, len(newMgPublicIds))
				for mgId := range newMgPublicIds {
					newMg := AllocManagedGroupMemberAccount()
					newMg.ManagedGroupId = mgId
					newMg.MemberId = acct.PublicId
					toAdd = append(toAdd, newMg)
				}
				if err := w.CreateItems(ctx, toAdd, db.NewOplogMsgs(&addOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add managed group member accounts"))
				}
				totalRowsAffected += len(toAdd)
				msgs = append(msgs, addOplogMsgs...)
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, mgTicket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		})
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op)
	}
	return totalRowsAffected, nil
}
