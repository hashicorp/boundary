// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// AddTargetHostSources provides the ability to add host sources (hostSourceIds)
// to a target (targetId). The target's current db version must match the
// targetVersion or an error will be returned.  The target and a list of current
// host source ids will be returned on success. Zero is not a valid value for the
// WithVersion option and will return an error.
func (r *Repository) AddTargetHostSources(ctx context.Context, targetId string, targetVersion uint32, hostSourceIds []string, _ ...Option) (Target, error) {
	const op = "target.(Repository).AddTargetHostSources"
	if targetId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if len(hostSourceIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing host source ids")
	}
	newHostSources := make([]*TargetHostSet, 0, len(hostSourceIds))
	for _, id := range hostSourceIds {
		ths, err := NewTargetHostSet(ctx, targetId, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory target host set"))
		}
		newHostSources = append(newHostSources, ths)
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}
	var metadata oplog.Metadata

	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}

	target := alloc()
	if err := target.SetPublicId(ctx, t.PublicId); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get set public id"))
	}
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)
	metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetProjectId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var currentHostSources []HostSource
	var currentCredSources []CredentialSource
	var updatedTarget Target
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			address, err := fetchAddress(ctx, reader, targetId)
			if err != nil && !errors.IsNotFoundError(err) {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target address"))
			}
			if address != nil && address.GetAddress() != "" {
				return errors.New(ctx, errors.Conflict, op, "unable to add host sources because a network address is directly assigned to the given target")
			}

			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(ctx, target)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			updatedTarget = target.Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			hostSourcesOplogMsgs := make([]*oplog.Message, 0, len(newHostSources))
			if err := w.CreateItems(ctx, newHostSources, db.NewOplogMsgs(&hostSourcesOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add target host sources"))
			}
			msgs = append(msgs, hostSourcesOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			currentHostSources, err = fetchHostSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current host sources after adds"))
			}
			currentCredSources, err = fetchCredentialSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current credential sources after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating sets"))
	}

	updatedTarget.SetHostSources(currentHostSources)
	updatedTarget.SetCredentialSources(currentCredSources)

	return updatedTarget, nil
}

// DeleteTargeHostSources deletes host sources from a target (targetId). The
// target's current db version must match the targetVersion or an error will be
// returned. Zero is not a valid value for the WithVersion option and will
// return an error.
func (r *Repository) DeleteTargetHostSources(ctx context.Context, targetId string, targetVersion uint32, hostSourceIds []string, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTargetHostSources"
	if targetId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if len(hostSourceIds) == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing host source ids")
	}
	deleteTargetHostSources := make([]*TargetHostSet, 0, len(hostSourceIds))
	for _, id := range hostSourceIds {
		ths, err := NewTargetHostSet(ctx, targetId, id)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory target host set"))
		}
		deleteTargetHostSources = append(deleteTargetHostSources, ths)
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}

	var metadata oplog.Metadata

	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}

	target := alloc()
	if err := target.SetPublicId(ctx, t.PublicId); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get set public id"))
	}
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)
	metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetProjectId(), kms.KeyPurposeOplog)
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
			targetTicket, err := w.GetTicket(ctx, target)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			hostSourcesOplogMsgs := make([]*oplog.Message, 0, len(deleteTargetHostSources))
			rowsDeleted, err := w.DeleteItems(ctx, deleteTargetHostSources, db.NewOplogMsgs(&hostSourcesOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target host sources"))
			}
			if rowsDeleted != len(deleteTargetHostSources) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("target host sources deleted %d did not match request for %d", rowsDeleted, len(deleteTargetHostSources)))
			}
			totalRowsDeleted += rowsDeleted
			msgs = append(msgs, hostSourcesOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
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

// SetTargetHostSources will set the target's host sources. Set add and/or delete
// target host sources as need to reconcile the existing sets with the sets
// requested. If hostSourceIds is empty, the target host sources will be cleared. Zero
// is not a valid value for the WithVersion option and will return an error.
func (r *Repository) SetTargetHostSources(ctx context.Context, targetId string, targetVersion uint32, hostSourceIds []string, _ ...Option) ([]HostSource, []CredentialSource, int, error) {
	const op = "target.(Repository).SetTargetHostSources"
	if targetId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}

	// NOTE: calculating that to set can safely happen outside of the write
	// transaction since we're using targetVersion to ensure that the only
	// operate on the same set of data from these queries that calculate the
	// set.

	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.
	foundThs, err := fetchHostSources(ctx, r.reader, targetId)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to search for existing target host sources"))
	}
	found := map[string]HostSource{}
	for _, s := range foundThs {
		found[s.Id()] = s
	}
	addHostSources := make([]*TargetHostSet, 0, len(hostSourceIds))
	for _, id := range hostSourceIds {
		if _, ok := found[id]; ok {
			// found a match, so do nothing (we want to keep it), but remove it
			// from found
			delete(found, id)
			continue
		}
		hs, err := NewTargetHostSet(ctx, targetId, id)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory target host set"))
		}
		addHostSources = append(addHostSources, hs)
	}
	deleteHostSources := make([]*TargetHostSet, 0, len(hostSourceIds))
	if len(found) > 0 {
		for _, s := range found {
			hs, err := NewTargetHostSet(ctx, targetId, s.Id())
			if err != nil {
				return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(" unable to create in memory target host set"))
			}
			deleteHostSources = append(deleteHostSources, hs)
		}
	}
	if len(addHostSources) == 0 && len(deleteHostSources) == 0 {
		return foundThs, nil, db.NoRowsAffected, nil
	}

	var metadata oplog.Metadata

	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}

	target := alloc()
	if err := target.SetPublicId(ctx, t.PublicId); err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get set public id"))
	}
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetProjectId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var totalRowsAffected int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			address, err := fetchAddress(ctx, reader, targetId)
			if err != nil && !errors.IsNotFoundError(err) {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target address"))
			}
			if address != nil && address.GetAddress() != "" {
				return errors.New(ctx, errors.Conflict, op, "unable to set host sources because a network address is directly assigned to the given target")
			}

			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(ctx, target)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("set target host sources: updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			// Write the new ones in
			if len(addHostSources) > 0 {
				hostSourceOplogMsgs := make([]*oplog.Message, 0, len(addHostSources))
				if err := w.CreateItems(ctx, addHostSources, db.NewOplogMsgs(&hostSourceOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add target host sources"))
				}
				totalRowsAffected += len(addHostSources)
				msgs = append(msgs, hostSourceOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// Anything we didn't take out of found needs to be removed
			if len(deleteHostSources) > 0 {
				hostSourceOplogMsgs := make([]*oplog.Message, 0, len(deleteHostSources))
				rowsDeleted, err := w.DeleteItems(ctx, deleteHostSources, db.NewOplogMsgs(&hostSourceOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target host source"))
				}
				if rowsDeleted != len(deleteHostSources) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("target host sources deleted %d did not match request for %d", rowsDeleted, len(deleteHostSources)))
				}
				totalRowsAffected += rowsDeleted
				msgs = append(msgs, hostSourceOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			currentHostSources, err := fetchHostSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target host sources after set"))
			}
			t.SetHostSources(currentHostSources)

			currentCredSources, err := fetchCredentialSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target credential sources after set"))
			}
			t.SetCredentialSources(currentCredSources)

			return nil
		},
	)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return t.HostSource, t.CredentialSources, totalRowsAffected, nil
}

func fetchHostSources(ctx context.Context, r db.Reader, targetId string) ([]HostSource, error) {
	const op = "target.fetchHostSources"
	var hostSets []*TargetSet
	if err := r.SearchWhere(ctx, &hostSets, "target_id = ?", []any{targetId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// FIXME: When we have direct host additions, there will need to be an
	// updated view that unions between sets and hosts, at which point the type
	// above will change. For now we just take the libraries and wrap them.
	if len(hostSets) == 0 {
		return nil, nil
	}
	ret := make([]HostSource, len(hostSets))
	for i, lib := range hostSets {
		ret[i] = lib
	}
	return ret, nil
}
