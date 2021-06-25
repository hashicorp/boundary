package target

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// AddTargetHostSets provides the ability to add host sets (hostSetIds) to a
// target (targetId).  The target's current db version must match the
// targetVersion or an error will be returned.   The target and a list of
// current host set ids will be returned on success. Zero is not a valid value
// for the WithVersion option and will return an error.
func (r *Repository) AddTargetHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, _ ...Option) (Target, []*TargetSet, []*TargetLibrary, error) {
	const op = "target.(Repository).AddTargetHostSets"
	if targetId == "" {
		return nil, nil, nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing version")
	}
	if len(hostSetIds) == 0 {
		return nil, nil, nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing host set ids")
	}
	newHostSets := make([]interface{}, 0, len(hostSetIds))
	for _, id := range hostSetIds {
		ths, err := NewTargetHostSet(targetId, id)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host set"))
		}
		newHostSets = append(newHostSets, ths)
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}
	var metadata oplog.Metadata
	var target interface{}
	switch t.Type {
	case TcpTargetType.String():
		tcpT := allocTcpTarget()
		tcpT.PublicId = t.PublicId
		tcpT.Version = targetVersion + 1
		target = &tcpT
		metadata = tcpT.oplog(oplog.OpType_OP_TYPE_UPDATE)
		metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
	default:
		return nil, nil, nil, errors.NewDeprecated(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var currentHostSets []*TargetSet
	var currentCredLibs []*TargetLibrary
	var updatedTarget interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget = target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated != 1 {
				return errors.NewDeprecated(errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			hostSetsOplogMsgs := make([]*oplog.Message, 0, len(newHostSets))
			if err := w.CreateItems(ctx, newHostSets, db.NewOplogMsgs(&hostSetsOplogMsgs)); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to add target host sets"))
			}
			msgs = append(msgs, hostSetsOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}
			currentHostSets, err = fetchSets(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current host sets after adds"))
			}
			currentCredLibs, err = fetchLibraries(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current credential libraries after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("error creating sets"))
	}
	return updatedTarget.(Target), currentHostSets, currentCredLibs, nil
}

// DeleteTargeHostSets deletes host sets from a target (targetId). The target's
// current db version must match the targetVersion or an error will be returned.
// Zero is not a valid value for the WithVersion option and will return an
// error.
func (r *Repository) DeleteTargeHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTargeHostSets"
	if targetId == "" {
		return db.NoRowsAffected, errors.NewDeprecated(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return db.NoRowsAffected, errors.NewDeprecated(errors.InvalidParameter, op, "missing version")
	}
	if len(hostSetIds) == 0 {
		return db.NoRowsAffected, errors.NewDeprecated(errors.InvalidParameter, op, "missing host set ids")
	}
	deleteTargeHostSets := make([]interface{}, 0, len(hostSetIds))
	for _, id := range hostSetIds {
		ths, err := NewTargetHostSet(targetId, id)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host set"))
		}
		deleteTargeHostSets = append(deleteTargeHostSets, ths)
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}

	var metadata oplog.Metadata
	var target interface{}
	switch t.Type {
	case TcpTargetType.String():
		tcpT := allocTcpTarget()
		tcpT.PublicId = t.PublicId
		tcpT.Version = targetVersion + 1
		target = &tcpT
		metadata = tcpT.oplog(oplog.OpType_OP_TYPE_UPDATE)
		metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
	default:
		return db.NoRowsAffected, errors.NewDeprecated(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var totalRowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated != 1 {
				return errors.NewDeprecated(errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			hostSetsOplogMsgs := make([]*oplog.Message, 0, len(deleteTargeHostSets))
			rowsDeleted, err := w.DeleteItems(ctx, deleteTargeHostSets, db.NewOplogMsgs(&hostSetsOplogMsgs))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to delete target host sets"))
			}
			if rowsDeleted != len(deleteTargeHostSets) {
				return errors.NewDeprecated(errors.MultipleRecords, op, fmt.Sprintf("target host sets deleted %d did not match request for %d", rowsDeleted, len(deleteTargeHostSets)))
			}
			totalRowsDeleted += rowsDeleted
			msgs = append(msgs, hostSetsOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op)
	}
	return totalRowsDeleted, nil
}

// SetTargetHostSets will set the target's host sets. Set add and/or delete
// target host sets as need to reconcile the existing sets with the sets
// requested. If hostSetIds is empty, the target host sets will be cleared. Zero
// is not a valid value for the WithVersion option and will return an error.
func (r *Repository) SetTargetHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, _ ...Option) ([]*TargetSet, []*TargetLibrary, int, error) {
	const op = "target.(Repository).SetTargetHostSets"
	if targetId == "" {
		return nil, nil, db.NoRowsAffected, errors.NewDeprecated(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, db.NoRowsAffected, errors.NewDeprecated(errors.InvalidParameter, op, "missing version")
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}

	// NOTE: calculating that to set can safely happen outside of the write
	// transaction since we're using targetVersion to ensure that the only
	// operate on the same set of data from these queries that calculate the
	// set.

	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.
	foundThs, err := fetchSets(ctx, r.reader, targetId)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to search for existing target host sets"))
	}
	found := map[string]*TargetSet{}
	for _, s := range foundThs {
		found[s.PublicId] = s
	}
	addHostSets := make([]interface{}, 0, len(hostSetIds))
	for _, id := range hostSetIds {
		if _, ok := found[id]; ok {
			// found a match, so do nothing (we want to keep it), but remove it
			// from found
			delete(found, id)
			continue
		}
		hs, err := NewTargetHostSet(targetId, id)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host set"))
		}
		addHostSets = append(addHostSets, hs)
	}
	deleteHostSets := make([]interface{}, 0, len(hostSetIds))
	if len(found) > 0 {
		for _, s := range found {
			hs, err := NewTargetHostSet(targetId, s.PublicId)
			if err != nil {
				return nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(" unable to create in memory target host set"))
			}
			deleteHostSets = append(deleteHostSets, hs)
		}
	}
	if len(addHostSets) == 0 && len(deleteHostSets) == 0 {
		return foundThs, nil, db.NoRowsAffected, nil
	}

	var metadata oplog.Metadata
	var target interface{}
	switch t.Type {
	case TcpTargetType.String():
		tcpT := allocTcpTarget()
		tcpT.PublicId = t.PublicId
		tcpT.Version = targetVersion + 1
		target = &tcpT
		metadata = tcpT.oplog(oplog.OpType_OP_TYPE_UPDATE)
	default:
		return nil, nil, db.NoRowsAffected, errors.NewDeprecated(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var totalRowsAffected int
	var currentHostSets []*TargetSet
	var currentCredLibs []*TargetLibrary
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated != 1 {
				return errors.NewDeprecated(errors.MultipleRecords, op, fmt.Sprintf("set target host sets: updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			// Write the new ones in
			if len(addHostSets) > 0 {
				hostSetOplogMsgs := make([]*oplog.Message, 0, len(addHostSets))
				if err := w.CreateItems(ctx, addHostSets, db.NewOplogMsgs(&hostSetOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add target host sets"))
				}
				totalRowsAffected += len(addHostSets)
				msgs = append(msgs, hostSetOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// Anything we didn't take out of found needs to be removed
			if len(deleteHostSets) > 0 {
				hostSetOplogMsgs := make([]*oplog.Message, 0, len(deleteHostSets))
				rowsDeleted, err := w.DeleteItems(ctx, deleteHostSets, db.NewOplogMsgs(&hostSetOplogMsgs))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to delete target host set"))
				}
				if rowsDeleted != len(deleteHostSets) {
					return errors.NewDeprecated(errors.MultipleRecords, op, fmt.Sprintf("target host sets deleted %d did not match request for %d", rowsDeleted, len(deleteHostSets)))
				}
				totalRowsAffected += rowsDeleted
				msgs = append(msgs, hostSetOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}

			currentHostSets, err = fetchSets(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current target host sets after set"))
			}
			currentCredLibs, err = fetchLibraries(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current target credential libraries after set"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	return currentHostSets, currentCredLibs, totalRowsAffected, nil
}

func fetchSets(ctx context.Context, r db.Reader, targetId string) ([]*TargetSet, error) {
	const op = "target.fetchSets"
	var hostSets []*TargetSet
	if err := r.SearchWhere(ctx, &hostSets, "target_id = ?", []interface{}{targetId}); err != nil {
		return nil, errors.Wrap(err, op)
	}
	if len(hostSets) == 0 {
		return nil, nil
	}
	return hostSets, nil
}
