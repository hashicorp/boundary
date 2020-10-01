package static

import (
	"context"
	"fmt"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

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
	members, err := r.newMembers(setId, hostIds)
	if err != nil {
		return nil, fmt.Errorf("add: static host set members: %w", err)
	}

	wrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("add: static host set members: unable to get oplog wrapper: %w", err)
	}

	var hosts []*Host
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		set := newHostSetForMembers(setId, version)
		metadata := set.oplog(oplog.OpType_OP_TYPE_CREATE)

		// Create host set members
		msgs, err := createMembers(ctx, w, members)
		if err != nil {
			return err
		}
		// Update host set version
		if err := updateVersion(ctx, w, wrapper, metadata, msgs, set, version); err != nil {
			return err
		}

		hosts, err = getHosts(ctx, reader, setId, unlimited)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("add: static host set members: %w", err)
	}

	return hosts, nil
}

func (r *Repository) newMembers(setId string, hostIds []string) ([]interface{}, error) {
	var members []interface{}
	for _, id := range hostIds {
		var m *HostSetMember
		m, err := NewHostSetMember(setId, id)
		if err != nil {
			return nil, fmt.Errorf("new members: %w", err)
		}
		members = append(members, m)
	}
	return members, nil
}

func createMembers(ctx context.Context, w db.Writer, members []interface{}) ([]*oplog.Message, error) {
	var msgs []*oplog.Message
	if err := w.CreateItems(ctx, members, db.NewOplogMsgs(&msgs)); err != nil {
		return nil, fmt.Errorf("unable to create host set members: %w", err)
	}
	return msgs, nil
}

func updateVersion(ctx context.Context, w db.Writer, wrapper wrapping.Wrapper, metadata oplog.Metadata, msgs []*oplog.Message, set *HostSet, version uint32) error {
	setMsg := new(oplog.Message)
	rowsUpdated, err := w.Update(ctx, set, []string{"Version"}, nil, db.NewOplogMsg(setMsg), db.WithVersion(&version))
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
}

const unlimited = -1

func getHosts(ctx context.Context, reader db.Reader, setId string, limit int) ([]*Host, error) {
	const whereNoLimit = `public_id in
       ( select host_id
           from static_host_set_member
          where set_id = $1
       )`

	const whereLimit = `public_id in
       ( select host_id
           from static_host_set_member
          where set_id = $1
          limit $2
       )`

	params := []interface{}{setId}
	var where string
	switch limit {
	case unlimited:
		where = whereNoLimit
	default:
		where = whereLimit
		params = append(params, limit)
	}

	var hosts []*Host
	if err := reader.SearchWhere(ctx, &hosts,
		where,
		params,
		db.WithLimit(limit),
	); err != nil {
		return nil, fmt.Errorf("get hosts: %w", err)
	}
	if len(hosts) == 0 {
		return nil, nil
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
	members, err := r.newMembers(setId, hostIds)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: %w", err)
	}

	wrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: unable to get oplog wrapper: %w", err)
	}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		set := newHostSetForMembers(setId, version)
		metadata := set.oplog(oplog.OpType_OP_TYPE_DELETE)

		// Delete host set members
		msgs, err := deleteMembers(ctx, w, members)
		if err != nil {
			return err
		}

		// Update host set version
		return updateVersion(ctx, w, wrapper, metadata, msgs, set, version)
	})

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: static host set members: %w", err)
	}
	return len(hostIds), nil
}

func deleteMembers(ctx context.Context, w db.Writer, members []interface{}) ([]*oplog.Message, error) {
	var msgs []*oplog.Message
	rowsDeleted, err := w.DeleteItems(ctx, members, db.NewOplogMsgs(&msgs))
	if err != nil {
		return nil, fmt.Errorf("unable to delete host set members: %w", err)
	}
	if rowsDeleted != len(members) {
		return nil, fmt.Errorf("set members deleted %d did not match request for %d", rowsDeleted, len(members))
	}
	return msgs, nil
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

	// NOTE(mgaffney) 08/2020: This establishes a new pattern for
	// calculating change sets for "SetMembers" methods. The changes are
	// calculated by the database using a single query. Existing
	// "SetMembers" methods retrieve all of the members of the set and
	// calculate the changes outside of the database. Our default moving
	// forward is to use SQL for calculations on the data in the database.

	// TODO(mgaffney) 08/2020: Change existing "SetMembers" methods to use
	// this pattern.
	changes, err := r.changes(ctx, setId, hostIds)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: %w", err)
	}
	var deletions, additions []interface{}
	for _, c := range changes {
		m, err := NewHostSetMember(setId, c.HostId)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: %w", err)
		}
		switch c.Action {
		case "delete":
			deletions = append(deletions, m)
		case "add":
			additions = append(additions, m)
		}
	}

	var hosts []*Host
	if len(changes) > 0 {
		wrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: unable to get oplog wrapper: %w", err)
		}

		_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
			set := newHostSetForMembers(setId, version)
			metadata := set.oplog(oplog.OpType_OP_TYPE_UPDATE)
			var msgs []*oplog.Message

			// Delete host set members
			if len(deletions) > 0 {
				deletedMsgs, err := deleteMembers(ctx, w, deletions)
				if err != nil {
					return err
				}
				msgs = append(msgs, deletedMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}

			// Add host set members
			if len(additions) > 0 {
				createdMsgs, err := createMembers(ctx, w, additions)
				if err != nil {
					return err
				}
				msgs = append(msgs, createdMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// Update host set version
			if err := updateVersion(ctx, w, wrapper, metadata, msgs, set, version); err != nil {
				return err
			}

			hosts, err = getHosts(ctx, reader, setId, unlimited)
			return err
		})

		if err != nil {
			return nil, db.NoRowsAffected, fmt.Errorf("set: static host set members: %w", err)
		}
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

	var params []interface{}
	params = append(params, setId)
	for _, v := range hostIds {
		params = append(params, v)
	}
	rows, err := r.reader.Query(ctx, query, params)
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
