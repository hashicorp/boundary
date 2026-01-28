// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

// AddTargetCredentialSources adds the credential source ids by purpose to the targetId in the repository.
// The target and the list of credential sources attached to the target, after ids are added,
// will be returned on success.
// The targetVersion must match the current version of the targetId in the repository.
func (r *Repository) AddTargetCredentialSources(ctx context.Context, targetId string, targetVersion uint32, idsByPurpose CredentialSources, _ ...Option) (Target, error) {
	const op = "target.(Repository).AddTargetCredentialSources"
	if targetId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
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

	addCredLibs, addStaticCreds, err := r.createSources(ctx, targetId, t.Subtype(), idsByPurpose)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	target := alloc()
	if err := target.SetPublicId(ctx, t.PublicId); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)
	metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetProjectId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var updatedTarget Target
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			numOplogMsgs := 1 + len(addCredLibs) + len(addStaticCreds)
			msgs := make([]*oplog.Message, 0, numOplogMsgs)
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
			if rowsUpdated == 0 {
				return errors.New(ctx, errors.VersionMismatch, op, "invalid target version")
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			if len(addCredLibs) > 0 {
				i := make([]*CredentialLibrary, 0, len(addCredLibs))
				for _, cl := range addCredLibs {
					i = append(i, cl)
				}
				credLibsOplogMsgs := make([]*oplog.Message, 0, len(addCredLibs))
				if err := w.CreateItems(ctx, i, db.NewOplogMsgs(&credLibsOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target credential library"))
				}
				msgs = append(msgs, credLibsOplogMsgs...)
			}

			if len(addStaticCreds) > 0 {
				i := make([]*StaticCredential, 0, len(addStaticCreds))
				for _, c := range addStaticCreds {
					i = append(i, c)
				}
				credStaticOplogMsgs := make([]*oplog.Message, 0, len(addStaticCreds))
				if err := w.CreateItems(ctx, i, db.NewOplogMsgs(&credStaticOplogMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target static credential"))
				}
				msgs = append(msgs, credStaticOplogMsgs...)
			}

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			hostSources, err := fetchHostSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve host sources after adding"))
			}
			updatedTarget.SetHostSources(hostSources)

			credSources, err := fetchCredentialSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve credential sources after adding"))
			}
			updatedTarget.SetCredentialSources(credSources)

			address, err := fetchAddress(ctx, reader, targetId)
			if err != nil && !errors.IsNotFoundError(err) {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve target address after adding"))
			}
			if address != nil {
				updatedTarget.SetAddress(address.GetAddress())
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return updatedTarget, nil
}

// DeleteTargetCredentialSources deletes credential sources from a target in the repository.
// The target's current db version must match the targetVersion or an error will be returned.
func (r *Repository) DeleteTargetCredentialSources(ctx context.Context, targetId string, targetVersion uint32, idsByPurpose CredentialSources, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTargetCredentialSources"
	if targetId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", targetId)))
	}
	var metadata oplog.Metadata

	deleteCredLibs, deleteStaticCred, err := r.createSources(ctx, targetId, t.Subtype(), idsByPurpose)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	target := alloc()
	if err := target.SetPublicId(ctx, t.PublicId); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)
	metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetProjectId(), kms.KeyPurposeOplog)
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
			if rowsUpdated == 0 {
				return errors.New(ctx, errors.VersionMismatch, op, "invalid target version")
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			if len(deleteCredLibs) > 0 {
				i := make([]*CredentialLibrary, 0, len(deleteCredLibs))
				for _, cl := range deleteCredLibs {
					i = append(i, cl)
				}

				credLibsOplogMsgs := make([]*oplog.Message, 0, len(deleteCredLibs))
				cnt, err := w.DeleteItems(ctx, i, db.NewOplogMsgs(&credLibsOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target credential libraries"))
				}
				if cnt != len(deleteCredLibs) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("credential libraries deleted %d did not match request for %d", rowsDeleted, len(deleteCredLibs)))
				}
				rowsDeleted += cnt
				msgs = append(msgs, credLibsOplogMsgs...)
			}

			if len(deleteStaticCred) > 0 {
				i := make([]*StaticCredential, 0, len(deleteStaticCred))
				for _, cl := range deleteStaticCred {
					i = append(i, cl)
				}

				staticCredOplogMsgs := make([]*oplog.Message, 0, len(deleteStaticCred))
				cnt, err := w.DeleteItems(ctx, i, db.NewOplogMsgs(&staticCredOplogMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target static credential"))
				}
				if cnt != len(deleteStaticCred) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("static credential deleted %d did not match request for %d", rowsDeleted, len(deleteCredLibs)))
				}
				rowsDeleted += cnt
				msgs = append(msgs, staticCredOplogMsgs...)
			}

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
func (r *Repository) SetTargetCredentialSources(ctx context.Context, targetId string, targetVersion uint32, ids CredentialSources, _ ...Option) ([]HostSource, []CredentialSource, int, error) {
	const op = "target.(Repository).SetTargetCredentialSources"
	if targetId == "" {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if targetVersion == 0 {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	var (
		addCredLibs   []*CredentialLibrary
		delCredLibs   []*CredentialLibrary
		addStaticCred []*StaticCredential
		delStaticCred []*StaticCredential
	)

	byPurpose := map[credential.Purpose][]string{
		credential.BrokeredPurpose:            ids.BrokeredCredentialIds,
		credential.InjectedApplicationPurpose: ids.InjectedApplicationCredentialIds,
	}
	for p, ids := range byPurpose {
		addL, delL, addS, delS, err := r.changes(ctx, targetId, ids, p)
		if err != nil {
			return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		addCredLibs = append(addCredLibs, addL...)
		delCredLibs = append(delCredLibs, delL...)
		addStaticCred = append(addStaticCred, addS...)
		delStaticCred = append(delStaticCred, delS...)
	}

	if len(addCredLibs)+len(delCredLibs)+len(addStaticCred)+len(delStaticCred) == 0 {
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

	vetCredentialSources, ok := subtypeRegistry.vetCredentialSourcesFunc(t.Subtype())
	if !ok {
		return nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", t.PublicId, t.Type))
	}
	// Validate add sources on target
	if err := vetCredentialSources(ctx, addCredLibs, addStaticCred); err != nil {
		return nil, nil, db.NoRowsAffected, err
	}

	target := alloc()
	if err := target.SetPublicId(ctx, t.PublicId); err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	target.SetVersion(targetVersion + 1)
	metadata = target.Oplog(oplog.OpType_OP_TYPE_UPDATE)

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetProjectId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsAffected int
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
			if rowsUpdated == 0 {
				return errors.New(ctx, errors.VersionMismatch, op, "invalid target version")
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated target and %d rows updated", rowsUpdated))
			}
			msgs = append(msgs, &targetOplogMsg)

			// add new credential libraries
			if len(addCredLibs) > 0 {
				i := make([]*CredentialLibrary, 0, len(addCredLibs))
				for _, cl := range addCredLibs {
					i = append(i, cl)
				}
				addMsgs := make([]*oplog.Message, 0, len(addCredLibs))
				if err := w.CreateItems(ctx, i, db.NewOplogMsgs(&addMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add target credential libraries"))
				}
				rowsAffected += len(addMsgs)
				msgs = append(msgs, addMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// delete existing credential libraries not part of set
			if len(delCredLibs) > 0 {
				i := make([]*CredentialLibrary, 0, len(delCredLibs))
				for _, cl := range delCredLibs {
					i = append(i, cl)
				}
				delMsgs := make([]*oplog.Message, 0, len(delCredLibs))
				rowsDeleted, err := w.DeleteItems(ctx, i, db.NewOplogMsgs(&delMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target credential libraries"))
				}
				if rowsDeleted != len(delMsgs) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("target credential libraries deleted %d did not match request for %d", rowsDeleted, len(delCredLibs)))
				}
				rowsAffected += rowsDeleted
				msgs = append(msgs, delMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}

			// add new static credential
			if len(addStaticCred) > 0 {
				i := make([]*StaticCredential, 0, len(addStaticCred))
				for _, cl := range addStaticCred {
					i = append(i, cl)
				}
				addMsgs := make([]*oplog.Message, 0, len(addStaticCred))
				if err := w.CreateItems(ctx, i, db.NewOplogMsgs(&addMsgs)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add target static credential "))
				}
				rowsAffected += len(addMsgs)
				msgs = append(msgs, addMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// delete existing static credentials not part of set
			if len(delStaticCred) > 0 {
				i := make([]*StaticCredential, 0, len(delStaticCred))
				for _, cl := range delStaticCred {
					i = append(i, cl)
				}
				delMsgs := make([]*oplog.Message, 0, len(delStaticCred))
				rowsDeleted, err := w.DeleteItems(ctx, i, db.NewOplogMsgs(&delMsgs))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target static credential"))
				}
				if rowsDeleted != len(delMsgs) {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("target static credential deleted %d did not match request for %d", rowsDeleted, len(delStaticCred)))
				}
				rowsAffected += rowsDeleted
				msgs = append(msgs, delMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			hostSources, err := fetchHostSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target host sets after add/delete"))
			}
			updatedTarget.SetHostSources(hostSources)

			credSources, err := fetchCredentialSources(ctx, reader, targetId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to retrieve current target credential sources after add/delete"))
			}
			updatedTarget.SetCredentialSources(credSources)

			return nil
		},
	)
	if err != nil {
		return nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return t.HostSource, t.CredentialSources, rowsAffected, nil
}

type changeQueryResult struct {
	Action   string
	Type     string
	SourceId string
}

func (r *Repository) changes(ctx context.Context, targetId string, ids []string, purpose credential.Purpose) (
	addCredLib, delCredLib []*CredentialLibrary,
	addStaticCred, delStaticCred []*StaticCredential,
	err error,
) {
	const op = "target.(Repository).changes"

	// TODO ensure that all cls have the same purpose as the given purpose?

	var inClauseSpots []string
	var params []any
	params = append(params, sql.Named("target_id", targetId), sql.Named("purpose", purpose))
	for idx, id := range ids {
		params = append(params, sql.Named(fmt.Sprintf("%d", idx+1), id))
		inClauseSpots = append(inClauseSpots, fmt.Sprintf("@%d", idx+1))
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}

	query := fmt.Sprintf(setChangesQuery, inClause)
	rows, err := r.reader.Query(ctx, query, params)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("query failed"))
	}
	defer rows.Close()

	for rows.Next() {
		var chg changeQueryResult
		if err := r.reader.ScanRows(ctx, rows, &chg); err != nil {
			return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		switch CredentialSourceType(chg.Type) {
		case LibraryCredentialSourceType:
			credType, err := getCredentialLibraryCredentialType(ctx, r.reader, chg.SourceId)
			if err != nil {
				return nil, nil, nil, nil, errors.Wrap(ctx, err, op)
			}
			lib, err := NewCredentialLibrary(ctx, targetId, chg.SourceId, purpose, credType)
			if err != nil {
				return nil, nil, nil, nil, errors.Wrap(ctx, err, op)
			}
			switch chg.Action {
			case "delete":
				delCredLib = append(delCredLib, lib)
			default:
				addCredLib = append(addCredLib, lib)
			}
		case StaticCredentialSourceType:
			cred, err := NewStaticCredential(ctx, targetId, chg.SourceId, purpose)
			if err != nil {
				return nil, nil, nil, nil, errors.Wrap(ctx, err, op)
			}
			switch chg.Action {
			case "delete":
				delStaticCred = append(delStaticCred, cred)
			default:
				addStaticCred = append(addStaticCred, cred)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("next rows error"))
	}
	return addCredLib, delCredLib, addStaticCred, delStaticCred, nil
}

func fetchCredentialSources(ctx context.Context, r db.Reader, targetId string) ([]CredentialSource, error) {
	const op = "target.fetchCredentialSources"
	var sources []*TargetCredentialSource
	if err := r.SearchWhere(ctx, &sources, "target_id = ?", []any{targetId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(sources) == 0 {
		return nil, nil
	}
	ret := make([]CredentialSource, len(sources))
	for i, source := range sources {
		ret[i] = source
	}
	return ret, nil
}

func (r *Repository) createSources(ctx context.Context, tId string, tSubtype globals.Subtype, credSources CredentialSources) ([]*CredentialLibrary, []*StaticCredential, error) {
	const op = "target.(Repository).createSources"

	// Get a list of unique ids being attached to the target, to be used for looking up the source type (library or static)
	ids := strutil.MergeSlices(credSources.BrokeredCredentialIds, credSources.InjectedApplicationCredentialIds)
	totalCreds := len(ids)
	ids = strutil.RemoveDuplicates(ids, false)
	if len(ids) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential sources")
	}

	// Fetch credentials from database to determine the type of credential
	var credView []*credentialSourceView
	if err := r.reader.SearchWhere(ctx, &credView, "public_id in (?)", []any{ids}); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("can't retrieve credentials"))
	}
	if len(ids) != len(credView) {
		return nil, nil, errors.New(ctx, errors.NotSpecificIntegrity, op,
			fmt.Sprintf("mismatch between request and returned source ids, expected %d got %d", len(ids), len(credView)))
	}

	// Create a map between credential source ID and it's type (library or static).
	// This will allow for a quick lookup when calling the corresponding New below
	credTypeById := make(map[string]CredentialSourceType, len(ids))
	for _, cv := range credView {
		credTypeById[cv.GetPublicId()] = CredentialSourceType(cv.GetType())
	}

	credLibs := make([]*CredentialLibrary, 0, totalCreds)
	staticCred := make([]*StaticCredential, 0, totalCreds)
	byPurpose := map[credential.Purpose][]string{
		credential.BrokeredPurpose:            credSources.BrokeredCredentialIds,
		credential.InjectedApplicationPurpose: credSources.InjectedApplicationCredentialIds,
	}
	for purpose, ids := range byPurpose {
		for _, id := range ids {
			switch credTypeById[id] {
			case LibraryCredentialSourceType:
				credType, err := getCredentialLibraryCredentialType(ctx, r.reader, id)
				if err != nil {
					return nil, nil, errors.Wrap(ctx, err, op)
				}
				lib, err := NewCredentialLibrary(ctx, tId, id, purpose, credType)
				if err != nil {
					return nil, nil, errors.Wrap(ctx, err, op)
				}
				credLibs = append(credLibs, lib)
			case StaticCredentialSourceType:
				cred, err := NewStaticCredential(ctx, tId, id, purpose)
				if err != nil {
					return nil, nil, errors.Wrap(ctx, err, op)
				}
				staticCred = append(staticCred, cred)
			}
		}
	}

	vetCredentialSources, ok := subtypeRegistry.vetCredentialSourcesFunc(tSubtype)
	if !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("is an unsupported target type %s", tSubtype))
	}
	if err := vetCredentialSources(ctx, credLibs, staticCred); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return credLibs, staticCred, nil
}

func getCredentialLibraryCredentialType(ctx context.Context, reader db.Reader, clId string) (string, error) {
	rows, err := reader.Query(ctx, getCredentialLibraryCredentialTypeQuery, []any{clId})
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var credType string
	for rows.Next() {
		if err := reader.ScanRows(ctx, rows, &credType); err != nil {
			return "", err
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	return credType, nil
}
