package static

import (
	"context"
	"database/sql"
	"fmt"

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
		rows, err = tx.Query(setMembersQueryLimit, setId, limit)
	default:
		rows, err = tx.Query(setMembersQueryNoLimit, setId)
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

	var hosts []*Host

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

	// NOTE(mgaffney): Currently, this cannot be done within the
	// transaction. Gorm panics when DB() is called during a transaction.
	tx, err := r.reader.DB()
	if err != nil {
		return nil, fmt.Errorf("get hosts: unable to get DB: %w", err)
	}

	rows, err := tx.Query(setMembersQueryNoLimit, setId)
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
// repository. It returns a slice of all hosts in setId. A host must belong
// to the same catalog as the set to be added. The version must match the
// current version of the setId in the repository.
func (r *Repository) SetSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) ([]*Host, error) {
	panic("not implemented")
}
