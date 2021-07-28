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

// AddTargetCredentialLibraries adds the clIds to the targetId in the repository. The target
// and the list of credential libraries attached to the target, after clIds are added,
// will be returned on success.
// The targetVersion must match the current version of the targetId in the repository.
func (r *Repository) AddTargetCredentialLibraries(ctx context.Context, targetId string, targetVersion uint32, clIds []string, _ ...Option) (Target, []*TargetSet, []*TargetLibrary, error) {
	const op = "target.(Repository).AddTargetCredentialLibraries"
	if targetId == "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if len(clIds) == 0 {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential library ids")
	}

	addCredLibs := make([]interface{}, 0, len(clIds))
	for _, id := range clIds {
		cl, err := NewCredentialLibrary(targetId, id)
		if err != nil {
			return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory credential library"))
		}
		addCredLibs = append(addCredLibs, cl)
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
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
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var hostSets []*TargetSet
	var credLibs []*TargetLibrary
	var updatedTarget interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget = target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated == 0 {
				return errors.New(ctx, errors.VersionMismatch, op, "invalid target version")
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			credLibsOplogMsgs := make([]*oplog.Message, 0, len(addCredLibs))
			if err := w.CreateItems(ctx, addCredLibs, db.NewOplogMsgs(&credLibsOplogMsgs)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target credential libraries"))
			}
			msgs = append(msgs, credLibsOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			hostSets, err = fetchSets(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve credential libraries after adding"))
			}
			credLibs, err = fetchLibraries(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve credential libraries after adding"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	return updatedTarget.(Target), hostSets, credLibs, nil
}

// DeleteTargetCredentialLibraries deletes credential libraries from a target in the repository.
// The target's current db version must match the targetVersion or an error will be returned.
func (r *Repository) DeleteTargetCredentialLibraries(ctx context.Context, targetId string, targetVersion uint32, clIds []string, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTargetCredentialLibraries"
	if targetId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if len(clIds) == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing credential library ids")
	}

	deleteCredLibs := make([]interface{}, 0, len(clIds))
	for _, id := range clIds {
		cl, err := NewCredentialLibrary(targetId, id)
		if err != nil {
			return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory credential library"))
		}
		deleteCredLibs = append(deleteCredLibs, cl)
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
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
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated == 0 {
				return errors.New(ctx, errors.VersionMismatch, op, "invalid target version")
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			credLibsOplogMsgs := make([]*oplog.Message, 0, len(deleteCredLibs))
			rowsDeleted, err = w.DeleteItems(ctx, deleteCredLibs, db.NewOplogMsgs(&credLibsOplogMsgs))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target credential libraries"))
			}
			if rowsDeleted != len(deleteCredLibs) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("credential libraries deleted %d did not match request for %d", rowsDeleted, len(deleteCredLibs)))
			}
			msgs = append(msgs, credLibsOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return rowsDeleted, nil
}

// SetTargetCredentialLibraries will set the target's credential libraries. Set will add
// and/or delete credential libraries as need to reconcile the existing credential libraries
// with the request. If clIds is empty, all the credential libraries will be cleared from the target.
func (r *Repository) SetTargetCredentialLibraries(ctx context.Context, targetId string, targetVersion uint32, clIds []string, _ ...Option) ([]*TargetSet, []*TargetLibrary, int, error) {
	const op = "target.(Repository).SetTargetCredentialLibraries"
	if targetId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	changes, err := r.changes(ctx, targetId, clIds)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if len(changes) == 0 {
		// Nothing needs to be changed, return early
		hostSets, err := fetchSets(ctx, r.reader, targetId)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		credLibs, err := fetchLibraries(ctx, r.reader, targetId)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		return hostSets, credLibs, db.NoRowsAffected, nil
	}

	var deleteCredLibs, addCredLibs []interface{}
	for _, c := range changes {
		cl, err := NewCredentialLibrary(targetId, c.LibraryId)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in memory target credential library"))
		}
		switch c.Action {
		case "delete":
			deleteCredLibs = append(deleteCredLibs, cl)
		case "add":
			addCredLibs = append(addCredLibs, cl)
		}
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
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
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsAffected int
	var hostSets []*TargetSet
	var credLibs []*TargetLibrary
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			updatedTarget := target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target version"))
			}
			if rowsUpdated == 0 {
				return errors.New(ctx, errors.VersionMismatch, op, "invalid target version")
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			// add new credential libraries
			if len(addCredLibs) > 0 {
				addMsgs := make([]*oplog.Message, 0, len(addCredLibs))
				if err := w.CreateItems(ctx, addCredLibs, db.NewOplogMsgs(&addMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add target credential libraries"))
				}
				rowsAffected += len(addMsgs)
				msgs = append(msgs, addMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// delete existing credential libraries not part of set
			if len(deleteCredLibs) > 0 {
				delMsgs := make([]*oplog.Message, 0, len(deleteCredLibs))
				rowsDeleted, err := w.DeleteItems(ctx, deleteCredLibs, db.NewOplogMsgs(&delMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target credential libraries"))
				}
				if rowsDeleted != len(delMsgs) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("target credential libraries deleted %d did not match request for %d", rowsDeleted, len(deleteCredLibs)))
				}
				rowsAffected += rowsDeleted
				msgs = append(msgs, delMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			hostSets, err = fetchSets(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target host sets after add/delete"))
			}
			credLibs, err = fetchLibraries(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target credential libraries after add/delete"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return hostSets, credLibs, rowsAffected, nil
}

type change struct {
	Action    string
	LibraryId string
}

func (r *Repository) changes(ctx context.Context, targetId string, clIds []string) ([]*change, error) {
	const op = "target.(Repository).changes"
	var inClauseSpots []string
	// starts at 2 because there is already a $1 in the query
	for i := 2; i < len(clIds)+2; i++ {
		inClauseSpots = append(inClauseSpots, fmt.Sprintf("$%d", i))
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}
	query := fmt.Sprintf(setChangesQuery, inClause)

	var params []interface{}
	params = append(params, targetId)
	for _, id := range clIds {
		params = append(params, id)
	}
	rows, err := r.reader.Query(ctx, query, params)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("query failed"))
	}
	defer rows.Close()

	var changes []*change
	for rows.Next() {
		var chg change
		if err := r.reader.ScanRows(rows, &chg); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		changes = append(changes, &chg)
	}
	return changes, nil
}

func fetchLibraries(ctx context.Context, r db.Reader, targetId string) ([]*TargetLibrary, error) {
	const op = "target.fetchLibraries"
	var libraries []*TargetLibrary
	if err := r.SearchWhere(ctx, &libraries, "target_id = ?", []interface{}{targetId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(libraries) == 0 {
		return nil, nil
	}
	return libraries, nil
}
