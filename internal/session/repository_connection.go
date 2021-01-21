package session

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// LookupConnection will look up a connection in the repository and return the connection
// with its states.  If the connection is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *Repository) LookupConnection(ctx context.Context, connectionId string, _ ...Option) (*Connection, []*ConnectionState, error) {
	const op = "session.(Repository).LookupConnection"
	if connectionId == "" {
		return nil, nil, errors.New(errors.InvalidParameter, op, "missing connectionId id")
	}
	connection := AllocConnection()
	connection.PublicId = connectionId
	var states []*ConnectionState
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &connection); err != nil {
				return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", connectionId)))
			}
			var err error
			if states, err = fetchConnectionStates(ctx, read, connectionId, db.WithOrder("start_time desc")); err != nil {
				return errors.Wrap(err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil
		}
		return nil, nil, errors.Wrap(err, op)
	}
	return &connection, states, nil
}

// ListConnections will sessions.  Supports the WithLimit and WithOrder options.
func (r *Repository) ListConnections(ctx context.Context, sessionId string, opt ...Option) ([]*Connection, error) {
	const op = "session.(Repository).ListConnections"
	opts := getOpts(opt...)
	var connections []*Connection
	err := r.list(ctx, &connections, "session_id = ?", []interface{}{sessionId}, opts) // pass options, so WithLimit and WithOrder are supported
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return connections, nil
}

// DeleteConnection will delete a connection from the repository.
func (r *Repository) DeleteConnection(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "session.(Repository).DeleteConnection"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing public id")
	}
	connection := AllocConnection()
	connection.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &connection); err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteConnection := connection.Clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteConnection,
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
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	return rowsDeleted, nil
}

func fetchConnectionStates(ctx context.Context, r db.Reader, connectionId string, opt ...db.Option) ([]*ConnectionState, error) {
	const op = "session.fetchConnectionStates"
	var states []*ConnectionState
	if err := r.SearchWhere(ctx, &states, "connection_id = ?", []interface{}{connectionId}, opt...); err != nil {
		return nil, errors.Wrap(err, op)
	}
	if len(states) == 0 {
		return nil, nil
	}
	return states, nil
}
