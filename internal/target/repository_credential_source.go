package target

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
)

// credentialLibrariesPurposeMap is used to group CredentialLibraries by purpose.
type credentialLibrariesPurposeMap map[string][]*CredentialLibrary

func (c credentialLibrariesPurposeMap) add(cl *CredentialLibrary) {
	var s []*CredentialLibrary
	var ok bool

	s, ok = c[cl.CredentialPurpose]
	if !ok {
		s = make([]*CredentialLibrary, 0, 1)
	}

	s = append(s, cl)
	c[cl.CredentialPurpose] = s
}

func newCredentialLibrariesPurposeMap(cls []*CredentialLibrary) credentialLibrariesPurposeMap {
	clpm := make(credentialLibrariesPurposeMap)
	for _, p := range credential.ValidPurposes {
		clpm[p.String()] = make([]*CredentialLibrary, 0)
	}
	for _, cl := range cls {
		clpm.add(cl)
	}
	return clpm
}

// AddTargetCredentialSources adds the cIds to the targetId in the repository. The target
// and the list of credential sources attached to the target, after cIds are added,
// will be returned on success.
// The targetVersion must match the current version of the targetId in the repository.
func (r *Repository) AddTargetCredentialSources(ctx context.Context, targetId string, targetVersion uint32, cls []*CredentialLibrary, _ ...Option) (Target, []HostSource, []CredentialSource, error) {
	const op = "target.(Repository).AddTargetCredentialSources"
	if targetId == "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if len(cls) == 0 {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential libraries")
	}

	addCredLibs := make([]interface{}, 0, len(cls))
	for _, cl := range cls {
		addCredLibs = append(addCredLibs, cl)
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}
	var metadata oplog.Metadata

	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}

	target := alloc()
	target.SetPublicId(ctx, t.PublicId)
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)
	metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var hostSources []HostSource
	var credSources []CredentialSource
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
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target credential sources"))
			}
			msgs = append(msgs, credLibsOplogMsgs...)

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			hostSources, err = fetchHostSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve host sources after adding"))
			}
			credSources, err = fetchCredentialSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve credential sources after adding"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	return updatedTarget.(Target), hostSources, credSources, nil
}

// DeleteTargetCredentialSources deletes credential sources from a target in the repository.
// The target's current db version must match the targetVersion or an error will be returned.
func (r *Repository) DeleteTargetCredentialSources(ctx context.Context, targetId string, targetVersion uint32, cls []*CredentialLibrary, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTargetCredentialSources"
	if targetId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if len(cls) == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing credential source ids")
	}

	deleteCredLibs := make([]interface{}, 0, len(cls))
	for _, cl := range cls {
		deleteCredLibs = append(deleteCredLibs, cl)
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
	target.SetPublicId(ctx, t.PublicId)
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)
	metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())

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
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target credential sources"))
			}
			if rowsDeleted != len(deleteCredLibs) {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("credential sources deleted %d did not match request for %d", rowsDeleted, len(deleteCredLibs)))
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

// SetTargetCredentialSources will set the target's credential sources. Set will add
// and/or delete credential sources as need to reconcile the existing credential sources
// with the request. If clIds is empty, all the credential sources will be cleared from the target.
func (r *Repository) SetTargetCredentialSources(ctx context.Context, targetId string, targetVersion uint32, cls []*CredentialLibrary, _ ...Option) ([]HostSource, []CredentialSource, int, error) {
	const op = "target.(Repository).SetTargetCredentialSources"
	if targetId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	clpm := newCredentialLibrariesPurposeMap(cls)

	var changes []*change

	for purpose, cls := range clpm {
		c, err := r.changes(ctx, targetId, cls, purpose)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		changes = append(changes, c...)
	}

	if len(changes) == 0 {
		// Nothing needs to be changed, return early
		hostSets, err := fetchHostSources(ctx, r.reader, targetId)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		credSources, err := fetchCredentialSources(ctx, r.reader, targetId)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		return hostSets, credSources, db.NoRowsAffected, nil
	}

	var deleteCredLibs, addCredLibs []interface{}
	for _, c := range changes {
		switch c.action {
		case "delete":
			deleteCredLibs = append(deleteCredLibs, c.credentialLibrary)
		case "add":
			addCredLibs = append(addCredLibs, c.credentialLibrary)
		}
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}
	var metadata oplog.Metadata

	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	target := alloc()
	target.SetPublicId(ctx, t.PublicId)
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsAffected int
	var hostSources []HostSource
	var credSources []CredentialSource
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

			hostSources, err = fetchHostSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target host sets after add/delete"))
			}
			credSources, err = fetchCredentialSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target credential sources after add/delete"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return hostSources, credSources, rowsAffected, nil
}

type change struct {
	action            string
	credentialLibrary *CredentialLibrary
}

type changeQueryResult struct {
	Action    string
	LibraryId string
}

func (r *Repository) changes(ctx context.Context, targetId string, cls []*CredentialLibrary, purpose string) ([]*change, error) {
	const op = "target.(Repository).changes"

	// TODO ensure that all cls have the same purpose as the given purpose?

	var inClauseSpots []string
	var params []interface{}
	params = append(params, sql.Named("target_id", targetId), sql.Named("purpose", purpose))
	for idx, cl := range cls {
		params = append(params, sql.Named(fmt.Sprintf("%d", idx+1), cl.CredentialLibraryId))
		inClauseSpots = append(inClauseSpots, fmt.Sprintf("@%d", idx+1))
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}

	query := fmt.Sprintf(setChangesQuery, inClause)
	rows, err := r.reader.Query(ctx, query, params)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("query failed"))
	}
	defer rows.Close()

	var changes []*change
	for rows.Next() {
		var chg changeQueryResult
		if err := r.reader.ScanRows(rows, &chg); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		changes = append(changes, &change{
			action: chg.Action,
			credentialLibrary: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					TargetId:            targetId,
					CredentialLibraryId: chg.LibraryId,
					CredentialPurpose:   purpose,
				},
			},
		})
	}
	return changes, nil
}

func fetchCredentialSources(ctx context.Context, r db.Reader, targetId string) ([]CredentialSource, error) {
	const op = "target.fetchCredentialSources"
	var libraries []*TargetLibrary
	if err := r.SearchWhere(ctx, &libraries, "target_id = ?", []interface{}{targetId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// FIXME: When we have static creds, there will need to be an updated view
	// that unions between libs and creds, at which point the type above will
	// change. For now we just take the libraries and wrap them.
	if len(libraries) == 0 {
		return nil, nil
	}
	ret := make([]CredentialSource, len(libraries))
	for i, lib := range libraries {
		ret[i] = lib
	}
	return ret, nil
}
