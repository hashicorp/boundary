package session

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
)

// CreateConnection inserts into the repository and returns the new Connection with
// its State of "Connected".  The following fields must be empty when creating a
// session: PublicId, BytesUp, BytesDown, ClosedReason, Version, CreateTime,
// UpdateTime.  No options are currently supported.
func (r *Repository) CreateConnection(ctx context.Context, newConnection *Connection, opt ...Option) (*Connection, *ConnectionState, error) {
	if newConnection == nil {
		return nil, nil, fmt.Errorf("create connection: missing connection: %w", db.ErrInvalidParameter)
	}
	if newConnection.PublicId != "" {
		return nil, nil, fmt.Errorf("create connection: public id is not empty: %w", db.ErrInvalidParameter)
	}
	if newConnection.BytesUp != 0 {
		return nil, nil, fmt.Errorf("create connection: bytes down is not empty: %w", db.ErrInvalidParameter)
	}
	if newConnection.BytesDown != 0 {
		return nil, nil, fmt.Errorf("create connection: bytes up is not empty: %w", db.ErrInvalidParameter)
	}
	if newConnection.ClosedReason != "" {
		return nil, nil, fmt.Errorf("create connection: closed reason is not empty: %w", db.ErrInvalidParameter)
	}
	if newConnection.Version != 0 {
		return nil, nil, fmt.Errorf("create connection: version is not empty: %w", db.ErrInvalidParameter)
	}
	if newConnection.CreateTime != nil {
		return nil, nil, fmt.Errorf("create connection: create time is not empty: %w", db.ErrInvalidParameter)
	}
	if newConnection.UpdateTime != nil {
		return nil, nil, fmt.Errorf("create connection: update time is not empty: %w", db.ErrInvalidParameter)
	}

	id, err := newConnectionId()
	if err != nil {
		return nil, nil, fmt.Errorf("create connection: %w", err)
	}
	newConnection.PublicId = id

	var returnedConnection *Connection
	var returnedState *ConnectionState
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			returnedConnection = newConnection.Clone().(*Connection)
			if err = w.Create(ctx, returnedConnection); err != nil {
				return err
			}
			var foundStates []*ConnectionState
			// trigger will create new "Connected" state
			if foundStates, err = fetchConnectionStates(ctx, read, returnedConnection.PublicId); err != nil {
				return err
			}
			if len(foundStates) != 1 {
				return fmt.Errorf("%d states found for new connection %s", len(foundStates), returnedConnection.PublicId)
			}
			returnedState = foundStates[0]
			if returnedState.Status != StatusConnected.String() {
				return fmt.Errorf("new connection %s state is not valid: %s", returnedConnection.PublicId, returnedState.Status)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create connection: %w", err)
	}
	return returnedConnection, returnedState, err
}

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
	var connections []*Connection
	err := r.list(ctx, &connections, "session_id = ?", []interface{}{sessionId}, opt...) // pass options, so WithLimit and WithOrder are supported
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

// UpdateConnection updates the repository entry for the connection, using the
// fieldMaskPaths.  Only BytesUp, BytesDown, and ClosedReason are mutable and
// will be set to NULL if set to a zero value and included in the fieldMaskPaths.
func (r *Repository) UpdateConnection(ctx context.Context, connection *Connection, version uint32, fieldMaskPaths []string, opt ...Option) (*Connection, []*ConnectionState, int, error) {
	if connection == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update connection: missing connection %w", db.ErrInvalidParameter)
	}
	if connection.PublicId == "" {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update connection: missing connection public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("BytesUp", f):
		case strings.EqualFold("BytesDown", f):
		case strings.EqualFold("ClosedReason", f):
		default:
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update connection: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"BytesUp":      connection.BytesUp,
			"BytesDown":    connection.BytesDown,
			"ClosedReason": connection.ClosedReason,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update connection: %w", db.ErrEmptyFieldMask)
	}

	var c *Connection
	var states []*ConnectionState
	var rowsUpdated int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			c = connection.Clone().(*Connection)
			rowsUpdated, err = w.Update(
				ctx,
				c,
				dbMask,
				nullFields,
			)
			if err != nil {
				return err
			}
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New("error more than 1 connection would have been updated ")
			}
			states, err = fetchConnectionStates(ctx, reader, c.PublicId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update connection: %w for %s", err, connection.PublicId)
	}
	return c, states, rowsUpdated, err
}

// UpdateConnectionState will update the connection's state using the connection id and its
// version.  No options are currently supported.
func (r *Repository) UpdateConnectionState(ctx context.Context, connectionId string, connectionVersion uint32, s ConnectionStatus, opt ...Option) (*Connection, []*ConnectionState, error) {
	if connectionId == "" {
		return nil, nil, fmt.Errorf("update connection state: missing session id %w", db.ErrInvalidParameter)
	}
	if connectionVersion == 0 {
		return nil, nil, fmt.Errorf("update connection state: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	if s == "" {
		return nil, nil, fmt.Errorf("update connection state: missing connection status: %w", db.ErrInvalidParameter)
	}

	newState, err := NewConnectionState(connectionId, s)
	if err != nil {
		return nil, nil, fmt.Errorf("update connection state: %w", err)
	}
	sessionConnection, _, err := r.LookupConnection(ctx, connectionId)
	if err != nil {
		return nil, nil, fmt.Errorf("update connection state: %w", err)
	}
	if sessionConnection == nil {
		return nil, nil, fmt.Errorf("update connection state: unable to look up connection for %s: %w", connectionId, err)
	}

	updatedConnection := AllocConnection()
	var returnedStates []*ConnectionState
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			// We need to update the connection version as that's the aggregate
			updatedConnection.PublicId = connectionId
			updatedConnection.Version = uint32(connectionVersion) + 1
			rowsUpdated, err := w.Update(ctx, &updatedConnection, []string{"Version"}, nil, db.WithVersion(&connectionVersion))
			if err != nil {
				return fmt.Errorf("unable to update connection version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("updated connection and %d rows updated", rowsUpdated)
			}
			if err := w.Create(ctx, newState); err != nil {
				return fmt.Errorf("unable to add new state: %w", err)
			}

			returnedStates, err = fetchConnectionStates(ctx, reader, connectionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("update connection state: error creating new state: %w", err)
	}
	return &updatedConnection, returnedStates, nil
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
