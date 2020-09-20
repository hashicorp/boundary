package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

// LookupConnection will look up a connection in the repository and return the connection
// with its states.  If the connection is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *Repository) LookupConnection(ctx context.Context, connectionId string, opt ...Option) (*Connection, []*ConnectionState, error) {
	if connectionId == "" {
		return nil, nil, fmt.Errorf("lookup connection: missing connectionId id: %w", db.ErrInvalidParameter)
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
				return fmt.Errorf("lookup connection: failed %w for %s", err, connectionId)
			}
			var err error
			if states, err = fetchConnectionStates(ctx, read, connectionId, db.WithOrder("start_time desc")); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("lookup connection: %w", err)
	}
	return &connection, states, nil
}

// ListConnections will sessions.  Supports the WithLimit and WithOrder options.
func (r *Repository) ListConnections(ctx context.Context, sessionId string, opt ...Option) ([]*Connection, error) {
	opts := getOpts(opt...)
	var connections []*Connection
	err := r.list(ctx, &connections, "session_id = ?", []interface{}{sessionId}, opts) // pass options, so WithLimit and WithOrder are supported
	if err != nil {
		return nil, fmt.Errorf("list connections: %w", err)
	}
	return connections, nil
}

// DeleteConnection will delete a connection from the repository.
func (r *Repository) DeleteConnection(ctx context.Context, publicId string, opt ...Option) (int, error) {
	if publicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete connection: missing public id %w", db.ErrInvalidParameter)
	}
	connection := AllocConnection()
	connection.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &connection); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete connection: failed %w for %s", err, publicId)
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
			if err == nil && rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return errors.New("error more than 1 connection would have been deleted")
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete connection: failed %w for %s", err, publicId)
	}
	return rowsDeleted, nil
}

func fetchConnectionStates(ctx context.Context, r db.Reader, connectionId string, opt ...db.Option) ([]*ConnectionState, error) {
	var states []*ConnectionState
	if err := r.SearchWhere(ctx, &states, "connection_id = ?", []interface{}{connectionId}, opt...); err != nil {
		return nil, fmt.Errorf("fetch connection states: %w", err)
	}
	if len(states) == 0 {
		return nil, nil
	}
	return states, nil
}
