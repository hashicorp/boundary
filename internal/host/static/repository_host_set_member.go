package static

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// AddSetMembers adds hostIds to setId in the repository. It returns a
// slice of all hosts in setId. A host must belong to the same catalog as
// the set to be added. The version must match the current version of the
// setId in the repository.
func (r *Repository) AddSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) ([]*Host, error) {
	const op = "static.(Repository).AddSetMembers"
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if setId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no set id")
	}
	if version == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no version")
	}
	if len(hostIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no host ids")
	}

	// Create in-memory host set members
	members, err := r.newMembers(ctx, setId, hostIds)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	wrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var hosts []*Host
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		set := newHostSetForMembers(setId, version)
		metadata := set.oplog(oplog.OpType_OP_TYPE_CREATE)

		// Create host set members
		msgs, err := createMembers(ctx, w, members)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		// Update host set version
		if err := updateVersion(ctx, w, wrapper, metadata, msgs, set, version); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		hosts, err = getHosts(ctx, reader, setId, unlimited)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return hosts, nil
}

func (r *Repository) newMembers(ctx context.Context, setId string, hostIds []string) ([]interface{}, error) {
	var members []interface{}
	for _, id := range hostIds {
		var m *HostSetMember
		m, err := NewHostSetMember(setId, id)
		if err != nil {
			return nil, errors.Wrap(ctx, err, "static.newMembers")
		}
		members = append(members, m)
	}
	return members, nil
}

func createMembers(ctx context.Context, w db.Writer, members []interface{}) ([]*oplog.Message, error) {
	var msgs []*oplog.Message
	if err := w.CreateItems(ctx, members, db.NewOplogMsgs(&msgs)); err != nil {
		return nil, errors.Wrap(ctx, err, "static.createMembers")
	}
	return msgs, nil
}

func updateVersion(ctx context.Context, w db.Writer, wrapper wrapping.Wrapper, metadata oplog.Metadata, msgs []*oplog.Message, set *HostSet, version uint32) error {
	const op = "static.updateVersion"
	setMsg := new(oplog.Message)
	rowsUpdated, err := w.Update(ctx, set, []string{"Version"}, nil, db.NewOplogMsg(setMsg), db.WithVersion(&version))
	switch {
	case err != nil:
		return errors.Wrap(ctx, err, op)
	case rowsUpdated == 0:
		return errors.New(ctx, errors.RecordNotFound, op, "no matching version for host set found")
	case rowsUpdated > 1:
		return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")

	}
	msgs = append(msgs, setMsg)

	// Write oplog
	ticket, err := w.GetTicket(set)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
	}
	if err := w.WriteOplogEntryWith(ctx, wrapper, ticket, metadata, msgs); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
	}
	return nil
}

const unlimited = -1

func getHosts(ctx context.Context, reader db.Reader, setId string, limit int) ([]*Host, error) {
	const whereNoLimit = `public_id in
       ( select host_id
           from static_host_set_member
          where set_id = ?
       )`

	const whereLimit = `public_id in
       ( select host_id
           from static_host_set_member
          where set_id = ?
          limit ?
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
		return nil, errors.Wrap(ctx, err, "static.getHosts")
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
	const op = "static.(Repository).DeleteSetMembers"
	if scopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if setId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no set id")
	}
	if version == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no version")
	}
	if len(hostIds) == 0 {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no host ids")
	}

	// Create in-memory host set members
	members, err := r.newMembers(ctx, setId, hostIds)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	wrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		set := newHostSetForMembers(setId, version)
		metadata := set.oplog(oplog.OpType_OP_TYPE_DELETE)

		// Delete host set members
		msgs, err := deleteMembers(ctx, w, members)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}

		// Update host set version
		err = updateVersion(ctx, w, wrapper, metadata, msgs, set, version)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	})

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return len(hostIds), nil
}

func deleteMembers(ctx context.Context, w db.Writer, members []interface{}) ([]*oplog.Message, error) {
	const op = "static.deleteMembers"
	var msgs []*oplog.Message
	rowsDeleted, err := w.DeleteItems(ctx, members, db.NewOplogMsgs(&msgs))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if rowsDeleted != len(members) {
		return nil, errors.E(ctx, errors.WithMsg(fmt.Sprintf("set members deleted %d did not match request for %d", rowsDeleted, len(members))))
	}
	return msgs, nil
}

// SetSetMembers replaces the hosts in setId with hostIds in the
// repository. It returns a slice of all hosts in setId and a count of
// hosts added or deleted. A host must belong to the same catalog as the
// set to be added. The version must match the current version of the setId
// in the repository. If hostIds is empty, all hosts will be removed setId.
func (r *Repository) SetSetMembers(ctx context.Context, scopeId string, setId string, version uint32, hostIds []string, opt ...Option) ([]*Host, int, error) {
	const op = "static.(Repository).SetSetMembers"
	if scopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if setId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no set id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no version")
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
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	var deletions, additions []interface{}
	for _, c := range changes {
		m, err := NewHostSetMember(setId, c.HostId)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
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
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
		}

		_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
			set := newHostSetForMembers(setId, version)
			metadata := set.oplog(oplog.OpType_OP_TYPE_UPDATE)
			var msgs []*oplog.Message

			// Delete host set members
			if len(deletions) > 0 {
				deletedMsgs, err := deleteMembers(ctx, w, deletions)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				msgs = append(msgs, deletedMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_DELETE.String())
			}

			// Add host set members
			if len(additions) > 0 {
				createdMsgs, err := createMembers(ctx, w, additions)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				msgs = append(msgs, createdMsgs...)
				metadata["op-type"] = append(metadata["op-type"], oplog.OpType_OP_TYPE_CREATE.String())
			}

			// Update host set version
			if err := updateVersion(ctx, w, wrapper, metadata, msgs, set, version); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			hosts, err = getHosts(ctx, reader, setId, unlimited)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		})

		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}
	return hosts, len(changes), nil
}

type change struct {
	Action string
	HostId string
}

func (r *Repository) changes(ctx context.Context, setId string, hostIds []string) ([]*change, error) {
	const op = "static.(Repository).changes"
	var inClauseSpots []string
	// starts at 2 because there is already a @1 in the query
	for i := 2; i < len(hostIds)+2; i++ {
		inClauseSpots = append(inClauseSpots, fmt.Sprintf("@%d", i))
	}
	inClause := strings.Join(inClauseSpots, ",")
	if inClause == "" {
		inClause = "''"
	}
	query := fmt.Sprintf(setChangesQuery, inClause)

	var params []interface{}
	params = append(params, sql.Named("1", setId))
	for idx, v := range hostIds {
		params = append(params, sql.Named(fmt.Sprintf("%d", idx+2), v))
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
