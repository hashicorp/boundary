// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/util"
)

// SetManagedGroupMemberships will set the managed groups for the given account
// ID. If mgs is empty, the set of groups the account belongs to will be
// cleared. It returns the set of managed group IDs.
//
// mgs contains the set of managed groups that matched. It must contain the
// group's version as this is used to ensure consistency between when the filter
// attached to the managed group was run and the point at which we are adding
// the account to the group.
func (r *Repository) SetManagedGroupMemberships(ctx context.Context, am *AuthMethod, acct *Account, mgs []*ManagedGroup, _ ...Option) ([]*ManagedGroupMemberAccount, int, error) {
	const op = "oidc.(Repository).SetManagedGroupMemberships"
	if am == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	}
	if am.AuthMethod == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing auth method store")
	}
	if am.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if am.ScopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing auth method scope id")
	}
	if acct == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing account")
	}
	if acct.Account == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing account store")
	}
	if acct.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing account id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	newMgPublicIds := make(map[string]bool, len(mgs))
	mgsToUpdate := make([]*ManagedGroup, 0, len(mgs))
	for _, mg := range mgs {
		if mg.Version == 0 {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("missing version for managed group %s", mg.PublicId))
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
		mgToUpdate.AuthMethodId = am.PublicId
		mgToUpdate.Version = mg.Version + 1
		mgsToUpdate = append(mgsToUpdate, mgToUpdate)
	}

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
			mgTicket, err := w.GetTicket(ctx, ticketMg)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket for oidc managed groups"))
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
			for _, mgToUpdate := range mgsToUpdate {
				var mgOplogMsg oplog.Message
				// mgToUpdate will have come in with an incremented version
				// already, but WithVersion needs the current version
				prevVersion := mgToUpdate.Version - 1
				rowsUpdated, err := w.Update(ctx, mgToUpdate, []string{"Version"}, nil, db.NewOplogMsg(&mgOplogMsg), db.WithVersion(&prevVersion))
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if rowsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated oidc managed group and %d rows updated", rowsUpdated))
				}
				msgs = append(msgs, &mgOplogMsg)
			}

			currentMemberships, err = r.ListManagedGroupMembershipsByMember(ctx, acct.PublicId, WithReader(reader), WithLimit(-1))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current managed group memberships before deletion"))
			}

			// Figure out which ones to delete and which ones we already have
			toDelete := make([]*ManagedGroupMemberAccount, 0, len(mgs))
			for _, currMg := range currentMemberships {
				currMgId := currMg.ManagedGroupId
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
			// anything left in newMgPublicIds should be added. However, if we
			// had no managed group to update, because none were passed in, but
			// also none to delete, we return at this point. Nothing will have
			// changed and nothing will be changed either.
			if len(mgs) == 0 && len(toDelete) == 0 {
				return errors.New(ctx, errors.GracefullyAborted, op, "nothing to do")
			}

			// Start with deletion
			if len(toDelete) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
				deleteOplogMsgs := make([]*oplog.Message, 0, len(toDelete))
				rowsDeleted, err := w.DeleteItems(ctx, toDelete, db.NewOplogMsgs(&deleteOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete managed group member accounts"))
				}
				if rowsDeleted != len(toDelete) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("managed group member accounts deleted %d did not match request for %d", rowsDeleted, len(toDelete)))
				}
				totalRowsAffected += rowsDeleted
				msgs = append(msgs, deleteOplogMsgs...)
			}

			// Now do insertion
			if len(newMgPublicIds) > 0 {
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
				addOplogMsgs := make([]*oplog.Message, 0, len(newMgPublicIds))
				toAdd := make([]*ManagedGroupMemberAccount, 0, len(newMgPublicIds))
				for mgId := range newMgPublicIds {
					newMg := AllocManagedGroupMemberAccount()
					newMg.ManagedGroupId = mgId
					newMg.MemberId = acct.PublicId
					toAdd = append(toAdd, newMg)
				}
				if err := w.CreateItems(ctx, toAdd, db.NewOplogMsgs(&addOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add managed group member accounts"))
				}
				totalRowsAffected += len(toAdd)
				msgs = append(msgs, addOplogMsgs...)
			}

			if len(msgs) > 0 {
				if err := w.WriteOplogEntryWith(ctx, oplogWrapper, mgTicket, metadata, msgs); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
				}
			}

			currentMemberships, err = r.ListManagedGroupMembershipsByMember(ctx, acct.PublicId, WithReader(reader), WithLimit(-1))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current managed group memberships after set"))
			}
			return nil
		})
	if err != nil && !errors.Match(errors.T(errors.GracefullyAborted), err) {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return currentMemberships, totalRowsAffected, nil
}

// ListManagedGroupMembershipsByMember lists managed group memberships via the
// member (account) ID and supports WithLimit option.
func (r *Repository) ListManagedGroupMembershipsByMember(ctx context.Context, withAcctId string, opt ...Option) ([]*ManagedGroupMemberAccount, error) {
	const op = "oidc.(Repository).ListManagedGroupMembershipsByMember"
	if withAcctId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing account id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	reader := r.reader
	if !util.IsNil(opts.withReader) {
		reader = opts.withReader
	}
	var mgs []*ManagedGroupMemberAccount
	err := reader.SearchWhere(ctx, &mgs, "member_id = ?", []any{withAcctId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return mgs, nil
}

// ListManagedGroupMembershipsByGroup lists managed group memberships via the
// group ID and supports WithLimit option.
func (r *Repository) ListManagedGroupMembershipsByGroup(ctx context.Context, withGroupId string, opt ...Option) ([]*ManagedGroupMemberAccount, error) {
	const op = "oidc.(Repository).ListManagedGroupMembershipsByGroup"
	if withGroupId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing managed group id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	reader := r.reader
	if !util.IsNil(opts.withReader) {
		reader = opts.withReader
	}
	var mgs []*ManagedGroupMemberAccount
	err := reader.SearchWhere(ctx, &mgs, "managed_group_id = ?", []any{withGroupId}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return mgs, nil
}
