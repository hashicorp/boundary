package static

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// ListSetMembers returns a slice of all hosts in setId.
func (r *Repository) ListSetMembers(ctx context.Context, setId string, opt ...Option) ([]*Host, error) {
	if setId == "" {
		return nil, fmt.Errorf("list: static host set members: missing set id: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	tx, err := r.reader.DB()
	if err != nil {
		return nil, fmt.Errorf("list: static host set members: %w", err)
	}

	var rows *sql.Rows
	switch {
	case limit > 0:
		rows, err = tx.QueryContext(ctx, setMembersQueryLimit, setId, limit)
	default:
		rows, err = tx.QueryContext(ctx, setMembersQueryNoLimit, setId)
	}
	if err != nil {
		return nil, fmt.Errorf("list: static host set members: %w", err)
	}
	defer rows.Close()

	var hosts []*Host

	for rows.Next() {
		var h Host
		if err := r.reader.ScanRows(rows, &h); err != nil {
			return nil, fmt.Errorf("list: static host set members: %w", err)
		}
		hosts = append(hosts, &h)
	}

	return hosts, nil
}

// AddSetMembers adds hostIds to setId in the repository. It returns a
// slice of all hosts in setId. A host must belong to the same catalog as
// the set to be added. The version must match the current version of the
// setId in the repository.
func (r *Repository) AddSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) ([]*Host, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("add: static host set members: missing scope id: %w", db.ErrInvalidParameter)
	}
	if setId == "" {
		return nil, fmt.Errorf("add: static host set members: missing set id: %w", db.ErrInvalidParameter)
	}
	if version == 0 {
		return nil, fmt.Errorf("add: static host set members: version is zero: %w", db.ErrInvalidParameter)
	}
	if len(hostIds) == 0 {
		return nil, fmt.Errorf("add: static host set members: empty hostIds: %w", db.ErrInvalidParameter)
	}

	// Create in-memory host set members
	var members []interface{}
	for _, id := range hostIds {
		var m *HostSetMember
		m, err := NewHostSetMember(setId, id)
		if err != nil {
			return nil, fmt.Errorf("add: static host set members: %w", err)
		}
		members = append(members, m)
	}

	wrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("add: static host set members: unable to get oplog wrapper: %w", err)
	}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		set := newHostSetForMembers(setId, version)
		metadata := set.oplog(oplog.OpType_OP_TYPE_CREATE)

		// Create host set members
		var msgs []*oplog.Message
		if err := w.CreateItems(ctx, members, db.NewOplogMsgs(&msgs)); err != nil {
			return fmt.Errorf("unable to create host set members: %w", err)
		}

		// Update host set version
		setMsg := new(oplog.Message)
		rowsUpdated, err := w.Update(
			ctx,
			set,
			[]string{"Version"},
			nil,
			db.NewOplogMsg(setMsg),
			db.WithVersion(&version),
		)
		switch {
		case err != nil:
			return fmt.Errorf("unable to update host set version: %w", err)
		case rowsUpdated > 1:
			return fmt.Errorf("unable to update host set version: %w", db.ErrMultipleRecords)
		}
		msgs = append(msgs, setMsg)

		// Write oplog
		ticket, err := w.GetTicket(set)
		if err != nil {
			return fmt.Errorf("unable to get ticket: %w", err)
		}
		if err := w.WriteOplogEntryWith(ctx, wrapper, ticket, metadata, msgs); err != nil {
			return fmt.Errorf("unable to write oplog: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("add: static host set members: %w", err)
	}

	// Get list of hosts
	var hosts []*Host

	// NOTE(mgaffney): Currently, this cannot be done within the
	// transaction. Gorm panics when DB() is called during a transaction.
	tx, err := r.reader.DB()
	if err != nil {
		return nil, fmt.Errorf("get hosts: unable to get DB: %w", err)
	}

	rows, err := tx.QueryContext(ctx, setMembersQueryNoLimit, setId)
	if err != nil {
		return nil, fmt.Errorf("get hosts: query failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var h Host
		if err := r.reader.ScanRows(rows, &h); err != nil {
			return nil, fmt.Errorf("get hosts: scan row failed: %w", err)
		}
		hosts = append(hosts, &h)
	}
	return hosts, nil
}

// DeleteSetMembers deletes hostIds from setId in the repository. It
// returns the number of hosts deleted from the set. The version must match
// the current version of the setId in the repository.
func (r *Repository) DeleteSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) (int, error) {
	if scopeId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: missing scope id: %w", db.ErrInvalidParameter)
	}
	if setId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: missing set id: %w", db.ErrInvalidParameter)
	}
	if version == 0 {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: version is zero: %w", db.ErrInvalidParameter)
	}
	if len(hostIds) == 0 {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: empty hostIds: %w", db.ErrInvalidParameter)
	}

	// Create in-memory host set members
	var members []interface{}
	for _, id := range hostIds {
		var m *HostSetMember
		m, err := NewHostSetMember(setId, id)
		if err != nil {
			return db.NoRowsAffected, fmt.Errorf("delete: static host set members: %w", err)
		}
		members = append(members, m)
	}

	wrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: unable to get oplog wrapper: %w", err)
	}

	var rowsDeleted int

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		set := newHostSetForMembers(setId, version)
		metadata := set.oplog(oplog.OpType_OP_TYPE_DELETE)

		// Delete host set members
		var msgs []*oplog.Message
		rowsDeleted, err = w.DeleteItems(ctx, members, db.NewOplogMsgs(&msgs))
		if err != nil {
			return fmt.Errorf("unable to delete host set members: %w", err)
		}
		if rowsDeleted != len(members) {
			return fmt.Errorf("set members deleted %d did not match request for %d", rowsDeleted, len(members))
		}

		// Update host set version
		setMsg := new(oplog.Message)
		rowsUpdated, err := w.Update(
			ctx,
			set,
			[]string{"Version"},
			nil,
			db.NewOplogMsg(setMsg),
			db.WithVersion(&version),
		)
		switch {
		case err != nil:
			return fmt.Errorf("unable to update host set version: %w", err)
		case rowsUpdated > 1:
			return fmt.Errorf("unable to update host set version: %w", db.ErrMultipleRecords)
		}
		msgs = append(msgs, setMsg)

		// Write oplog
		ticket, err := w.GetTicket(set)
		if err != nil {
			return fmt.Errorf("unable to get ticket: %w", err)
		}
		if err := w.WriteOplogEntryWith(ctx, wrapper, ticket, metadata, msgs); err != nil {
			return fmt.Errorf("unable to write oplog: %w", err)
		}

		return nil
	})

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: %w", err)
	}
	return rowsDeleted, nil
}

// SetSetMembers replaces the hosts in setId with hostIds in the
// repository. It returns a slice of all hosts in setId and a count of
// hosts added or deleted. A host must belong to the same catalog as the
// set to be added. The version must match the current version of the setId
// in the repository. If hostIds is empty, all hosts will be removed setId.
func (r *Repository) SetSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) ([]*Host, int, error) {
	if scopeId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: missing scope id: %w", db.ErrInvalidParameter)
	}
	if setId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: missing set id: %w", db.ErrInvalidParameter)
	}
	if version == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: version is zero: %w", db.ErrInvalidParameter)
	}

	// TODO(mgaffney) 08/2020: Oplog does not currently support bulk
	// operations. Push these operations to the database once bulk
	// operations are added.

	changes, err := r.changes(ctx, setId, hostIds)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: %w", err)
	}
	var deleteMembers, addMembers []interface{}
	for _, c := range changes {
		m, err := NewHostSetMember(setId, c.HostId)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: %w", err)
		}
		switch c.Action {
		case "delete":
			deleteMembers = append(deleteMembers, m)
		case "add":
			addMembers = append(addMembers, m)
		}
	}

	if len(changes) != 0 {
		wrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: unable to get oplog wrapper: %w", err)
		}

		_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
			set := newHostSetForMembers(setId, version)
			metadata := set.oplog(oplog.OpType_OP_TYPE_UPDATE)
			var msgs []*oplog.Message

			// Delete host set members
			if len(deleteMembers) > 0 {
				rowsDeleted, err := w.DeleteItems(ctx, deleteMembers, db.NewOplogMsgs(&msgs))
				if err != nil {
					return fmt.Errorf("unable to delete host set members: %w", err)
				}
				if rowsDeleted != len(deleteMembers) {
					return fmt.Errorf("set members deleted %d did not match request for %d", rowsDeleted, len(deleteMembers))
				}
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}

			// Add host set members
			if len(addMembers) > 0 {
				if err := w.CreateItems(ctx, addMembers, db.NewOplogMsgs(&msgs)); err != nil {
					return fmt.Errorf("unable to create host set members: %w", err)
				}
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// Update host set version
			setMsg := new(oplog.Message)
			rowsUpdated, err := w.Update(
				ctx,
				set,
				[]string{"Version"},
				nil,
				db.NewOplogMsg(setMsg),
				db.WithVersion(&version),
			)
			switch {
			case err != nil:
				return fmt.Errorf("unable to update host set version: %w", err)
			case rowsUpdated > 1:
				return fmt.Errorf("unable to update host set version: %w", db.ErrMultipleRecords)
			}
			msgs = append(msgs, setMsg)

			// Write oplog
			ticket, err := w.GetTicket(set)
			if err != nil {
				return fmt.Errorf("unable to get ticket: %w", err)
			}
			if err := w.WriteOplogEntryWith(ctx, wrapper, ticket, metadata, msgs); err != nil {
				return fmt.Errorf("unable to write oplog: %w", err)
			}

			return nil
		})

		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: %w", err)
		}
	}

	// Get list of hosts
	var hosts []*Host

	// NOTE(mgaffney): Currently, this cannot be done within the
	// transaction. Gorm panics when DB() is called during a transaction.
	tx, err := r.reader.DB()
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("get hosts: unable to get DB: %w", err)
	}

	rows, err := tx.QueryContext(ctx, setMembersQueryNoLimit, setId)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("get hosts: query failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var h Host
		if err := r.reader.ScanRows(rows, &h); err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("get hosts: scan row failed: %w", err)
		}
		hosts = append(hosts, &h)
	}
	return hosts, len(changes), nil
}

type change struct {
	Action string
	HostId string
}

func (r *Repository) changes(ctx context.Context, setId string, hostIds []string) ([]*change, error) {
	var inClauseSpots []string
	// starts at 2 because there is already a $1 in the query
	for i := 2; i < len(hostIds)+2; i++ {
		inClauseSpots = append(inClauseSpots, fmt.Sprintf("$%d", i))
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}
	query := fmt.Sprintf(setChangesQuery, inClause)

	tx, err := r.reader.DB()
	if err != nil {
		return nil, fmt.Errorf("changes: unable to get DB: %w", err)
	}

	var params []interface{}
	params = append(params, setId)
	for _, v := range hostIds {
		params = append(params, v)
	}
	rows, err := tx.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("changes: query failed: %w", err)
	}
	defer rows.Close()

	var changes []*change
	for rows.Next() {
		var chg change
		if err := r.reader.ScanRows(rows, &chg); err != nil {
			return nil, fmt.Errorf("changes: scan row failed: %w", err)
		}
		changes = append(changes, &chg)
	}
	return changes, nil
}
