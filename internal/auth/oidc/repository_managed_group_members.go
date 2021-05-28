package oidc

import (
	"context"
	"fmt"
	"log"

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
func (r *Repository) SetManagedGroupMemberships(ctx context.Context, am *AuthMethod, acct *Account, mgs []*ManagedGroup, _ ...Option) ([]*ManagedGroupMemberAccount, int, error) {
	const op = "oidc.(Repository).SetManagedGroupMembers"
	if am == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if am.AuthMethod == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing auth method store")
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
	if acct.Account == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing account store")
	}
	if acct.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing account id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	newMgPublicIds := make(map[string]bool, len(mgs))
	mgsToUpdate := make([]*ManagedGroup, 0, len(mgs))
	for _, mg := range mgs {
		if mg.Version == 0 {
			return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("missing version for managed group %s", mg.PublicId))
		}
		if newMgPublicIds[mg.PublicId] {
			// We've already seen this -- could be a duplicate in the incoming
			// MGs. We don't want to add it again because the version won't be
			// correct, and it's unnecessary.
			continue
		}
		newMgPublicIds[mg.PublicId] = true
		mgToUpdate := AllocManagedGroup()
		mgToUpdate.PublicId = mg.PublicId
		mgToUpdate.AuthMethodId = mg.AuthMethodId
		mgToUpdate.Version = mg.Version + 1
		mgsToUpdate = append(mgsToUpdate, mgToUpdate)
		log.Println("to update", mgToUpdate.PublicId, mgToUpdate.Version)
	}
	log.Println(len(mgs))
	log.Println(len(newMgPublicIds))
	log.Println(len(mgsToUpdate))

	ticketMg := AllocManagedGroup()
	var totalRowsAffected int
	var currentMemberships []*ManagedGroupMemberAccount
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
			for i, mgToUpdate := range mgsToUpdate {
				var mgOplogMsg oplog.Message
				log.Println("updating", mgToUpdate.PublicId, mgToUpdate.Version)

				cloned := mgToUpdate.Clone()
				if err := r.reader.LookupByPublicId(ctx, cloned); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("uh oh"))
				}
				log.Println("updating 2", cloned.PublicId, cloned.Version)

				rowsUpdated, err := w.Update(ctx, mgToUpdate, []string{"Version"}, nil, db.NewOplogMsg(&mgOplogMsg), db.WithVersion(&mgs[i].Version))
				if err != nil {
					return errors.Wrap(err, op)
				}
				if rowsUpdated != 1 {
					log.Println("bad", mgToUpdate.PublicId, mgToUpdate.Version)
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated oidc managed group and %d rows updated", rowsUpdated))
				}
				log.Println("good", mgToUpdate.PublicId, mgToUpdate.Version)
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
				log.Println("found existing membership", currMgId)
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
					log.Println("deleting", delMg.ManagedGroupId, delMg.MemberId)
				}
			}

			// At this point, anything in toDelete should be deleted, and
			// anything left in newMgPublicIds should be added. However, if we
			// had no managed group to update, because none were passed in, but
			// also none to delete, we return at this point. Nothing will have
			// changed and nothing will be changed either.
			//
			// FIXME: Not returning an error means we don't abort the
			// transaction, but we don't really want the function as a whole to
			// error. Figure out the right way to do this.
			/*
				if len(mgs) == 0 && len(toDelete) == 0 {
					return nil
				}
			*/

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

			// we need a new repo that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
			}
			currentMemberships, err = txRepo.ListManagedGroupMembershipsByMember(ctx, acct.PublicId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current principal roles after sets"))
			}
			return nil
		})
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	return currentMemberships, totalRowsAffected, nil
}

// ListManagedGroupMembershipsByMember lists managed group memberships via the
// member (account) ID and supports WithLimit option.
func (r *Repository) ListManagedGroupMembershipsByMember(ctx context.Context, withAcctId string, opt ...Option) ([]*ManagedGroupMemberAccount, error) {
	const op = "oidc.(Repository).ListManagedGroupMembershipsByMember"
	if withAcctId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing account id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var mgs []*ManagedGroupMemberAccount
	err := r.reader.SearchWhere(ctx, &mgs, "member_id = ?", []interface{}{withAcctId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return mgs, nil
}
