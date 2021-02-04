package target

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
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
	const op = "target.NewRepository"
	if r == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil kms")
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
// with its host set ids and host ids. If the target is not found, it will
// return nil, nil, nil, nil. No options are currently supported.
func (r *Repository) LookupTarget(ctx context.Context, publicIdOrName string, opt ...Option) (Target, []*TargetSet, []*TargetHostView, error) {
	const op = "target.(Repository).LookupTarget"
	opts := getOpts(opt...)

	if publicIdOrName == "" {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing public id")
	}

	var where []string
	var whereArgs []interface{}
	nameEmpty := opts.withName == ""
	scopeIdEmpty := opts.withScopeId == ""
	scopeNameEmpty := opts.withScopeName == ""
	if !nameEmpty {
		if opts.withName != publicIdOrName {
			return nil, nil, nil, errors.New(errors.InvalidParameter, op, "name passed in but does not match publicId")
		}
		where, whereArgs = append(where, "lower(name) = lower(?)"), append(whereArgs, opts.withName)
		switch {
		case scopeIdEmpty && scopeNameEmpty:
			return nil, nil, nil, errors.New(errors.InvalidParameter, op, "using name but both scope ID and scope name are empty")
		case !scopeIdEmpty && !scopeNameEmpty:
			return nil, nil, nil, errors.New(errors.InvalidParameter, op, "using name but both scope ID and scope name are set")
		case !scopeIdEmpty:
			where, whereArgs = append(where, "scope_id = ?"), append(whereArgs, opts.withScopeId)
		case !scopeNameEmpty:
			where, whereArgs = append(where, "scope_id = (select public_id from iam_scope where lower(name) = lower(?))"), append(whereArgs, opts.withScopeName)
		default:
			return nil, nil, nil, errors.New(errors.InvalidParameter, op, "unknown combination of parameters")
		}
	} else {
		switch {
		case !scopeIdEmpty:
			return nil, nil, nil, errors.New(errors.InvalidParameter, op, "passed in scope ID when using target ID for lookup")
		case !scopeNameEmpty:
			return nil, nil, nil, errors.New(errors.InvalidParameter, op, "passed in scope name when using target ID for lookup")
		}
	}

	target := allocTargetView()
	target.PublicId = publicIdOrName
	var hostSets []*TargetSet
	var hosts []*TargetHostView
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var lookupErr error
			switch where {
			case nil:
				lookupErr = read.LookupById(ctx, &target)
			default:
				target.PublicId = ""
				lookupErr = read.LookupWhere(ctx, &target, strings.Join(where, " and "), whereArgs...)
			}
			if lookupErr != nil {
				return errors.Wrap(lookupErr, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicIdOrName)))
			}
			var err error
			if hostSets, err = fetchSets(ctx, read, target.PublicId); err != nil {
				return errors.Wrap(err, op)
			}
			if hosts, err = fetchHosts(ctx, read, target.PublicId); err != nil {
				return errors.Wrap(err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, errors.Wrap(err, op)
	}
	subType, err := target.targetSubType()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op)
	}
	return subType, hostSets, hosts, nil
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

func fetchHosts(ctx context.Context, r db.Reader, targetId string) ([]*TargetHostView, error) {
	const op = "target.fetchHosts"
	var hosts []*TargetHostView
	if err := r.SearchWhere(ctx, &hosts, "target_id = ?", []interface{}{targetId}); err != nil {
		return nil, errors.Wrap(err, op)
	}
	if len(hosts) == 0 {
		return nil, nil
	}
	return hosts, nil
}

// ListTargets in targets in a scope.  Supports the WithScopeId, WithLimit, WithTargetType options.
func (r *Repository) ListTargets(ctx context.Context, opt ...Option) ([]Target, error) {
	const op = "target.(Repository).ListTargets"
	opts := getOpts(opt...)
	if len(opts.withScopeIds) == 0 && opts.withUserId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "must specify either scope id or user id")
	}
	// TODO (jimlambrt 8/2020) - implement WithUserId() optional filtering.
	var where []string
	var args []interface{}
	if len(opts.withScopeIds) != 0 {
		where, args = append(where, "scope_id in (?)"), append(args, opts.withScopeIds)
	}
	if opts.withTargetType != nil {
		where, args = append(where, "type = ?"), append(args, opts.withTargetType.String())
	}

	var foundTargets []*targetView
	err := r.list(ctx, &foundTargets, strings.Join(where, " and "), args, opt...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	targets := make([]Target, 0, len(foundTargets))

	for _, t := range foundTargets {
		subType, err := t.targetSubType()
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		targets = append(targets, subType)
	}
	return targets, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	const op = "target.(Repository).list"
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	if err := r.reader.SearchWhere(ctx, resources, where, args, dbOpts...); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// DeleteTarget will delete a target from the repository.
func (r *Repository) DeleteTarget(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTarget"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	t := allocTargetView()
	t.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
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
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", publicId, t.Type))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
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
			if err != nil {
				return errors.Wrap(err, op)
			}
			if rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return errors.New(errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op)
	}
	return rowsDeleted, nil
}

// update a target in the db repository with an oplog entry.
// It currently supports no options.
func (r *Repository) update(ctx context.Context, target Target, version uint32, fieldMaskPaths []string, setToNullPaths []string, _ ...Option) (Target, []*TargetSet, []*TargetHostView, int, error) {
	const op = "target.(Repository).update"
	if version == 0 {
		return nil, nil, nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing version")
	}
	if target == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "nil target")
	}
	cloner, ok := target.(Cloneable)
	if !ok {
		return nil, nil, nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "target is not cloneable")
	}
	dbOpts := []db.Option{
		db.WithVersion(&version),
	}
	scopeId := target.GetScopeId()
	if scopeId == "" {
		t := allocTargetView()
		t.PublicId = target.GetPublicId()
		if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
			return nil, nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("lookup failed for %s", t.PublicId)))
		}
		scopeId = t.ScopeId
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	metadata := target.oplog(oplog.OpType_OP_TYPE_UPDATE)
	dbOpts = append(dbOpts, db.WithOplog(oplogWrapper, metadata))

	var rowsUpdated int
	var returnedTarget interface{}
	var hostSets []*TargetSet
	var hosts []*TargetHostView
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
				return errors.Wrap(err, op)
			}
			if rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New(errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}

			if hostSets, err = fetchSets(ctx, reader, target.GetPublicId()); err != nil {
				return errors.Wrap(err, op)
			}

			if hosts, err = fetchHosts(ctx, reader, target.GetPublicId()); err != nil {
				return errors.Wrap(err, op)
			}

			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	return returnedTarget.(Target), hostSets, hosts, rowsUpdated, nil
}

// AddTargetHostSets provides the ability to add host sets (hostSetIds) to a
// target (targetId).  The target's current db version must match the
// targetVersion or an error will be returned.   The target and a list of
// current host set ids will be returned on success. Zero is not a valid value
// for the WithVersion option and will return an error.
func (r *Repository) AddTargetHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, _ ...Option) (Target, []*TargetSet, []*TargetHostView, error) {
	const op = "target.(Repository).AddTargetHostSets"
	if targetId == "" {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing version")
	}
	if len(hostSetIds) == 0 {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing host set ids")
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
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var currentHostSets []*TargetSet
	var currentHosts []*TargetHostView
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
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
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
			currentHosts, err = fetchHosts(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current hosts after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("error creating sets"))
	}
	return updatedTarget.(Target), currentHostSets, currentHosts, nil
}

// DeleteTargetHostSets deletes host sets from a target (targetId). The target's
// current db version must match the targetVersion or an error will be returned.
// Zero is not a valid value for the WithVersion option and will return an
// error.
func (r *Repository) DeleteTargetHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTargetHostSets"
	if targetId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing version")
	}
	if len(hostSetIds) == 0 {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing host set ids")
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
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
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
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			hostSetsOplogMsgs := make([]*oplog.Message, 0, len(deleteTargeHostSets))
			rowsDeleted, err := w.DeleteItems(ctx, deleteTargeHostSets, db.NewOplogMsgs(&hostSetsOplogMsgs))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to delete target host sets"))
			}
			if rowsDeleted != len(deleteTargeHostSets) {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("target host sets deleted %d did not match request for %d", rowsDeleted, len(deleteTargeHostSets)))
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
func (r *Repository) SetTargetHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, _ ...Option) ([]*TargetSet, int, error) {
	const op = "target.(Repository).SetTargetHostSets"
	if targetId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing version")
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}

	// NOTE: calculating what to set can safely happen outside of the write
	// transaction since we're using targetVersion to ensure that the only
	// operate on the same set of data from these queries that calculate the
	// set.

	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.
	foundThs, err := fetchSets(ctx, r.reader, targetId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to search for existing target host sets"))
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
			return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host set"))
		}
		addHostSets = append(addHostSets, hs)
	}
	deleteHostSets := make([]interface{}, 0, len(hostSetIds))
	if len(found) > 0 {
		for _, s := range found {
			hs, err := NewTargetHostSet(targetId, s.PublicId)
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host set"))
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
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
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
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated != 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("set target host sets: updated target and %d rows updated", rowsUpdated))
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
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("target host sets deleted %d did not match request for %d", rowsDeleted, len(deleteHostSets)))
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
			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	return currentHostSets, totalRowsAffected, nil
}

// AddTargetHosts provides the ability to add hosts (hostIds) to a target
// (targetId). The target's current db version must match the targetVersion or
// an error will be returned. The target and a list of current host ids will be
// returned on success. Zero is not a valid value for the WithVersion option and
// will return an error.
func (r *Repository) AddTargetHosts(ctx context.Context, targetId string, targetVersion uint32, hostIds []string, _ ...Option) (Target, []*TargetSet, []*TargetHostView, error) {
	const op = "target.(Repository).AddTargetHosts"
	if targetId == "" {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing version")
	}
	if len(hostIds) == 0 {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing host ids")
	}
	newHosts := make([]interface{}, 0, len(hostIds))
	for _, id := range hostIds {
		th, err := NewTargetHost(targetId, id)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host"))
		}
		newHosts = append(newHosts, th)
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
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	var currentHostSets []*TargetSet
	var currentHosts []*TargetHostView
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
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			hostsOplogMsgs := make([]*oplog.Message, 0, len(newHosts))
			if err := w.CreateItems(ctx, newHosts, db.NewOplogMsgs(&hostsOplogMsgs)); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to add target host"))
			}
			msgs = append(msgs, hostsOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}
			currentHostSets, err = fetchSets(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current host sets after adds"))
			}
			currentHosts, err = fetchHosts(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current hosts after adds"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("error creating sets"))
	}
	return updatedTarget.(Target), currentHostSets, currentHosts, nil
}

// DeleteTargetHosts deletes hosts from a target (targetId). The target's
// current db version must match the targetVersion or an error will be returned.
// Zero is not a valid value for the WithVersion option and will return an
// error.
func (r *Repository) DeleteTargetHosts(ctx context.Context, targetId string, targetVersion uint32, hostIds []string, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTargetHosts"
	if targetId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing version")
	}
	if len(hostIds) == 0 {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing host ids")
	}
	deleteTargetHosts := make([]interface{}, 0, len(hostIds))
	for _, id := range hostIds {
		th, err := NewTargetHost(targetId, id)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host"))
		}
		deleteTargetHosts = append(deleteTargetHosts, th)
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
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
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
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			hostsOplogMsgs := make([]*oplog.Message, 0, len(deleteTargetHosts))
			rowsDeleted, err := w.DeleteItems(ctx, deleteTargetHosts, db.NewOplogMsgs(&hostsOplogMsgs))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to delete target hosts"))
			}
			if rowsDeleted != len(deleteTargetHosts) {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("target hosts deleted %d did not match request for %d", rowsDeleted, len(deleteTargetHosts)))
			}
			totalRowsDeleted += rowsDeleted
			msgs = append(msgs, hostsOplogMsgs...)

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

// SetTargetHosts will set the target's hosts. Set add and/or delete
// target hosts as need to reconcile the existing hosts with the hosts
// requested. If hostIds is empty, the target hosts will be cleared. Zero
// is not a valid value for the WithVersion option and will return an error.
func (r *Repository) SetTargetHosts(ctx context.Context, targetId string, targetVersion uint32, hostIds []string, _ ...Option) ([]*TargetHostView, int, error) {
	const op = "target.(Repository).SetTargetHosts"
	if targetId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing version")
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}

	// NOTE: calculating what to set can safely happen outside of the write
	// transaction since we're using targetVersion to ensure that the only
	// operate on the same set of data from these queries that calculate the
	// set.

	// TODO(mgaffney) 08/2020: Use SQL to calculate changes.
	foundThv, err := fetchHosts(ctx, r.reader, targetId)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to search for existing target hosts"))
	}
	found := map[string]*TargetHostView{}
	for _, s := range foundThv {
		found[s.PublicId] = s
	}
	addHosts := make([]interface{}, 0, len(hostIds))
	for _, id := range hostIds {
		if _, ok := found[id]; ok {
			// found a match, so do nothing (we want to keep it), but remove it
			// from found
			delete(found, id)
			continue
		}
		h, err := NewTargetHost(targetId, id)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host"))
		}
		addHosts = append(addHosts, h)
	}
	deleteHosts := make([]interface{}, 0, len(hostIds))
	if len(found) > 0 {
		for _, s := range found {
			h, err := NewTargetHost(targetId, s.PublicId)
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host"))
			}
			deleteHosts = append(deleteHosts, h)
		}
	}
	if len(addHosts) == 0 && len(deleteHosts) == 0 {
		return foundThv, db.NoRowsAffected, nil
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
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var totalRowsAffected int
	var currentHosts []*TargetHostView
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
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("set target hosts: updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			// Write the new ones in
			if len(addHosts) > 0 {
				hostOplogMsgs := make([]*oplog.Message, 0, len(addHosts))
				if err := w.CreateItems(ctx, addHosts, db.NewOplogMsgs(&hostOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add target hosts"))
				}
				totalRowsAffected += len(addHosts)
				msgs = append(msgs, hostOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// Anything we didn't take out of found needs to be removed
			if len(deleteHosts) > 0 {
				hostOplogMsgs := make([]*oplog.Message, 0, len(deleteHosts))
				rowsDeleted, err := w.DeleteItems(ctx, deleteHosts, db.NewOplogMsgs(&hostOplogMsgs))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to delete target host"))
				}
				if rowsDeleted != len(deleteHosts) {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("target hosts deleted %d did not match request for %d", rowsDeleted, len(deleteHosts)))
				}
				totalRowsAffected += rowsDeleted
				msgs = append(msgs, hostOplogMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}

			currentHosts, err = fetchHosts(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to retrieve current target hosts after set"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op)
	}
	return currentHosts, totalRowsAffected, nil
}
