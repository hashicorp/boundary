package target

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

var (
	ErrMetadataScopeNotFound = errors.New("scope not found for metadata")
)

// Clonable provides a cloning interface
type Cloneable interface {
	Clone() interface{}
}

// Repository is the target database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new target Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if kms == nil {
		return nil, errors.New("error creating db repository with nil kms")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
	}, nil
}

// LookupTarget will look up a target in the repository and return the target
// with its host set ids.  If the target is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *Repository) LookupTarget(ctx context.Context, publicId string, opt ...Option) (Target, []*TargetSet, error) {
	if publicId == "" {
		return nil, nil, fmt.Errorf("lookup target: missing private id: %w", db.ErrInvalidParameter)
	}
	target := allocTargetView()
	target.PublicId = publicId
	var hostSets []*TargetSet
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &target); err != nil {
				return fmt.Errorf("lookup target: failed %w for %s", err, publicId)
			}
			var err error
			if hostSets, err = fetchSets(ctx, read, target.PublicId); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("lookup target: %w", err)
	}
	subType, err := target.targetSubType()
	if err != nil {
		return nil, nil, fmt.Errorf("lookup target: %w", err)
	}
	return subType, hostSets, nil
}

func fetchSets(ctx context.Context, r db.Reader, targetId string) ([]*TargetSet, error) {
	var hostSets []*TargetSet
	if err := r.SearchWhere(ctx, &hostSets, "target_id = ?", []interface{}{targetId}); err != nil {
		return nil, fmt.Errorf("fetch host sets: %w", err)
	}
	if len(hostSets) == 0 {
		return nil, nil
	}
	return hostSets, nil
}

// ListTargets in targets in a scope.  Supports the WithScopeId, WithLimit, WithTargetType options.
func (r *Repository) ListTargets(ctx context.Context, opt ...Option) ([]Target, error) {
	opts := getOpts(opt...)
	if opts.withScopeId == "" && opts.withUserId == "" {
		return nil, fmt.Errorf("list targets: must specify either a scope id or user id: %w", db.ErrInvalidParameter)
	}
	// TODO (jimlambrt 8/2020) - implement WithUserId() optional filtering.
	var where []string
	var args []interface{}
	if opts.withScopeId != "" {
		where, args = append(where, "scope_id = ?"), append(args, opts.withScopeId)
	}
	if opts.withTargetType != nil {
		where, args = append(where, "type = ?"), append(args, opts.withTargetType.String())
	}

	var foundTargets []*targetView
	err := r.list(ctx, &foundTargets, strings.Join(where, " and "), args, opt...)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}

	targets := make([]Target, 0, len(foundTargets))

	for _, t := range foundTargets {
		subType, err := t.targetSubType()
		if err != nil {
			return nil, fmt.Errorf("list targets: %w", err)
		}
		targets = append(targets, subType)
	}
	return targets, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	return r.reader.SearchWhere(ctx, resources, where, args, dbOpts...)
}

// DeleteTarget will delete a target from the repository.
func (r *Repository) DeleteTarget(ctx context.Context, publicId string, opt ...Option) (int, error) {
	if publicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete target: missing public id %w", db.ErrInvalidParameter)
	}
	t := allocTargetView()
	t.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete target: failed %w for %s", err, publicId)
	}
	var metadata oplog.Metadata
	var deleteTarget interface{}
	switch t.Type {
	case TcpTargetType.String():
		tcpT := allocTcpTarget()
		tcpT.PublicId = publicId
		deleteTarget = &tcpT
		metadata = tcpT.oplog(oplog.OpType_OP_TYPE_DELETE)
	default:
		return db.NoRowsAffected, fmt.Errorf("delete target: %s is an unsupported target type %s", publicId, t.Type)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete target: unable to get oplog wrapper: %w", err)
	}

	var rowsDeleted int
	var deleteResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteResource = deleteTarget.(Cloneable).Clone()
			rowsDeleted, err = w.Delete(
				ctx,
				deleteResource,
				db.WithOplog(oplogWrapper, metadata),
			)
			if err == nil && rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	return rowsDeleted, err
}

// update a target in the db repository with an oplog entry.
// It currently supports no options.
func (r *Repository) update(ctx context.Context, target Target, version uint32, fieldMaskPaths []string, setToNullPaths []string, opt ...Option) (Target, []*TargetSet, int, error) {
	if version == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	if target == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: target is nil: %w", db.ErrInvalidParameter)
	}
	cloner, ok := target.(Cloneable)
	if !ok {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update: target is not Cloneable: %w", db.ErrInvalidParameter)
	}
	dbOpts := []db.Option{
		db.WithVersion(&version),
	}
	scopeId := target.GetScopeId()
	if scopeId == "" {
		t := allocTargetView()
		t.PublicId = target.GetPublicId()
		if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update: lookup failed %w for %s", err, t.PublicId)
		}
		scopeId = t.ScopeId
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("unable to get oplog wrapper: %w", err)
	}
	metadata := target.oplog(oplog.OpType_OP_TYPE_UPDATE)
	dbOpts = append(dbOpts, db.WithOplog(oplogWrapper, metadata))

	var rowsUpdated int
	var returnedTarget interface{}
	var hostSets []*TargetSet
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			returnedTarget = cloner.Clone()
			rowsUpdated, err = w.Update(
				ctx,
				returnedTarget,
				fieldMaskPaths,
				setToNullPaths,
				dbOpts...,
			)
			if err != nil {
				return err
			}
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return fmt.Errorf("error more than 1 target would have been updated: %w", db.ErrMultipleRecords)
			}
			var err error
			if hostSets, err = fetchSets(ctx, reader, target.GetPublicId()); err != nil {
				return err
			}
			return err
		},
	)
	return returnedTarget.(Target), hostSets, rowsUpdated, err
}

// AddTargetHostSets provides the ability to add host sets (hostSetIds) to a
// target (targetId).  The target's current db version must match the
// targetVersion or an error will be returned.   The target and a list of
// current host set ids will be returned on success. Zero is not a valid value
// for the WithVersion option and will return an error.
func (r *Repository) AddTargetHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, opt ...Option) (Target, []*TargetSet, error) {
	if targetId == "" {
		return nil, nil, fmt.Errorf("add target host sets: missing target id: %w", db.ErrInvalidParameter)
	}
	if targetVersion == 0 {
		return nil, nil, fmt.Errorf("add target host sets: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	if len(hostSetIds) == 0 {
		return nil, nil, fmt.Errorf("add target host sets: missing host set ids: %w", db.ErrInvalidParameter)
	}
	newHostSets := make([]interface{}, 0, len(hostSetIds))
	for _, id := range hostSetIds {
		ths, err := NewTargetHostSet(targetId, id)
		if err != nil {
			return nil, nil, fmt.Errorf("add target host sets: unable to create in memory target host set: %w", err)
		}
		newHostSets = append(newHostSets, ths)
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, fmt.Errorf("add target host sets: failed %w for %s", err, targetId)
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
		return nil, nil, fmt.Errorf("delete target host sets: %s is an unsupported target type %s", t.PublicId, t.Type)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, fmt.Errorf("add target host sets: unable to get oplog wrapper: %w", err)
	}
	var currentHostSets []*TargetSet
	var updatedTarget interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return fmt.Errorf("add target host sets: unable to get ticket: %w", err)
			}
			updatedTarget = target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return fmt.Errorf("add target host sets: unable to update target version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("add target host sets: updated target and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &targetOplogMsg)

			hostSetsOplogMsgs := make([]*oplog.Message, 0, len(newHostSets))
			if err := w.CreateItems(ctx, newHostSets, db.NewOplogMsgs(&hostSetsOplogMsgs)); err != nil {
				return fmt.Errorf("add target host sets: unable to add target host sets: %w", err)
			}
			msgs = append(msgs, hostSetsOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return fmt.Errorf("add target host sets: unable to write oplog: %w", err)
			}
			currentHostSets, err = fetchSets(ctx, reader, targetId)
			if err != nil {
				return fmt.Errorf("add target host sets: unable to retrieve current host sets after adds: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("add target host sets: error creating sets: %w", err)
	}
	return updatedTarget.(Target), currentHostSets, nil
}

// DeleteTargeHostSets deletes host sets from a target (targetId). The target's
// current db version must match the targetVersion or an error will be returned.
// Zero is not a valid value for the WithVersion option and will return an
// error.
func (r *Repository) DeleteTargeHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, opt ...Option) (int, error) {
	if targetId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete target host sets: missing target id: %w", db.ErrInvalidParameter)
	}
	if targetVersion == 0 {
		return db.NoRowsAffected, fmt.Errorf("delete target host sets: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	if len(hostSetIds) == 0 {
		return db.NoRowsAffected, fmt.Errorf("delete target host sets: missing host set ids: %w", db.ErrInvalidParameter)
	}
	deleteTargeHostSets := make([]interface{}, 0, len(hostSetIds))
	for _, id := range hostSetIds {
		ths, err := NewTargetHostSet(targetId, id)
		if err != nil {
			return db.NoRowsAffected, fmt.Errorf("delete target host sets: unable to create in memory target host set: %w", err)
		}
		deleteTargeHostSets = append(deleteTargeHostSets, ths)
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete target host sets: failed %w for %s", err, targetId)
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
		return db.NoRowsAffected, fmt.Errorf("delete target host sets: %s is an unsupported target type %s", t.PublicId, t.Type)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete target host sets: unable to get oplog wrapper: %w", err)
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
				return fmt.Errorf("delete target host sets: unable to get ticket: %w", err)
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return fmt.Errorf("delete target host sets: unable to update target version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("delete target host sets: updated target and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &targetOplogMsg)

			hostSetsOplogMsgs := make([]*oplog.Message, 0, len(deleteTargeHostSets))
			rowsDeleted, err := w.DeleteItems(ctx, deleteTargeHostSets, db.NewOplogMsgs(&hostSetsOplogMsgs))
			if err != nil {
				return fmt.Errorf("delete target host sets: unable to delete target host sets: %w", err)
			}
			if rowsDeleted != len(deleteTargeHostSets) {
				return fmt.Errorf("delete target host sets: target host sets deleted %d did not match request for %d", rowsDeleted, len(deleteTargeHostSets))
			}
			totalRowsDeleted += rowsDeleted
			msgs = append(msgs, hostSetsOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return fmt.Errorf("delete target host sets: unable to write oplog: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete target host sets: error deleting target host sets: %w", err)
	}
	return totalRowsDeleted, nil
}

// SetTargetHostSets will set the target's host sets. Set add and/or delete
// target host sets as need to reconcile the existing sets with the sets
// requested. If hostSetIds is empty, the target host sets will be cleared. Zero
// is not a valid value for the WithVersion option and will return an error.
func (r *Repository) SetTargetHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, opt ...Option) ([]*TargetSet, int, error) {
	if targetId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("set target host sets: missing target id: %w", db.ErrInvalidParameter)
	}
	if targetVersion == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("set target host sets: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set target host sets: failed %w for %s", err, targetId)
	}

	// NOTE: calculating that to set can safely happen outside of the write
	// transaction since we're using targetVersion to ensure that the only
	// operate on the same set of data from these queries that calculate the
	// set.

	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.
	foundThs, err := fetchSets(ctx, r.reader, targetId)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set target host sets: unable to search for existing target host sets: %w", err)
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
			return nil, db.NoRowsAffected, fmt.Errorf("set target host set: unable to create in memory target host set: %w", err)
		}
		addHostSets = append(addHostSets, hs)
	}
	deleteHostSets := make([]interface{}, 0, len(hostSetIds))
	if len(found) > 0 {
		for _, s := range found {
			hs, err := NewTargetHostSet(targetId, s.PublicId)
			if err != nil {
				return nil, db.NoRowsAffected, fmt.Errorf("set target host set: unable to create in memory target host set: %w", err)
			}
			deleteHostSets = append(deleteHostSets, hs)
		}
	}
	if len(addHostSets) == 0 && len(deleteHostSets) == 0 {
		return foundThs, db.NoRowsAffected, nil
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
		return nil, db.NoRowsAffected, fmt.Errorf("set target host sets: %s is an unsupported target type %s", t.PublicId, t.Type)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set target host sets: unable to get oplog wrapper: %w", err)
	}

	var totalRowsAffected int
	var currentHostSets []*TargetSet
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return fmt.Errorf("set target host sets: unable to get ticket: %w", err)
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return fmt.Errorf("set target host sets: unable to update target version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("set target host sets: updated target and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &targetOplogMsg)

			// Write the new ones in
			if len(addHostSets) > 0 {
				hostSetOplogMsgs := make([]*oplog.Message, 0, len(addHostSets))
				if err := w.CreateItems(ctx, addHostSets, db.NewOplogMsgs(&hostSetOplogMsgs)); err != nil {
					return fmt.Errorf("unable to add target host sets during set: %w", err)
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
					return fmt.Errorf("set target host sets: unable to delete target host set: %w", err)
				}
				if rowsDeleted != len(deleteHostSets) {
					return fmt.Errorf("set target host sets: target host sets deleted %d did not match request for %d", rowsDeleted, len(deleteHostSets))
				}
				totalRowsAffected += rowsDeleted
				msgs = append(msgs, hostSetOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return fmt.Errorf("set target host sets: unable to write oplog: %w", err)
			}

			currentHostSets, err = fetchSets(ctx, reader, targetId)
			if err != nil {
				return fmt.Errorf("set target host sets: unable to retrieve current target host sets after set: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("target host sets: error setting target host sets: %w", err)
	}
	return currentHostSets, totalRowsAffected, nil
}
