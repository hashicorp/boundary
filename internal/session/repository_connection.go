// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/kms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ConnectionRepository is the session connection database repository.
type ConnectionRepository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int

	// workerStateDelay is used by queries to account for a delay in state propagation between
	// worker and controller
	workerStateDelay time.Duration
}

// NewConnectionRepository creates a new session Connection Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewConnectionRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*ConnectionRepository, error) {
	const op = "sessionConnection.NewRepository"
	if r == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}

	return &ConnectionRepository{
		reader:           r,
		writer:           w,
		kms:              kms,
		defaultLimit:     opts.withLimit,
		workerStateDelay: opts.withWorkerStateDelay,
	}, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit.  Supports WithOrder option.
func (r *ConnectionRepository) list(ctx context.Context, resources any, where string, args []any, opt ...Option) error {
	const op = "session.(ConnectionRepository).list"
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	switch opts.withOrderByCreateTime {
	case db.AscendingOrderBy:
		dbOpts = append(dbOpts, db.WithOrder("create_time asc"))
	case db.DescendingOrderBy:
		dbOpts = append(dbOpts, db.WithOrder("create_time"))
	}
	if err := r.reader.SearchWhere(ctx, resources, where, args, dbOpts...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *ConnectionRepository) updateBytesUpBytesDown(ctx context.Context, conns ...*Connection) error {
	const op = "session.(ConnectionRepository).updateBytesUpBytesDown"
	if len(conns) == 0 {
		return nil
	}

	updateMask := []string{"BytesUp", "BytesDown"}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			for _, c := range conns {
				_, err := w.Update(
					ctx,
					&Connection{PublicId: c.PublicId, BytesUp: c.BytesUp, BytesDown: c.BytesDown},
					updateMask,
					nil,
					// The last update to these two fields should come from our
					// connection closure logic, which does not use this
					// function (see the closeConnections func). Therefore, here
					// we shouldn't update bytes up and down if the connection
					// has already been closed. This also guards against
					// potential data races where a connection closure request
					// and a worker statistics update happen close to each other in
					// terms of timing.
					db.WithWhere("closed_reason is null"),
				)
				if err != nil {
					// Returning an error will rollback the entire transaction.
					// We don't want to bail out of an update batch if just one
					// of the connections fails to update, but we still log it.
					event.WriteError(ctx, op, fmt.Errorf("failed to update bytes up and down for connection id %q: %w", c.GetPublicId(), err))
					continue
				}
			}

			return nil
		})

	return err
}

// AuthorizeConnection will check to see if a connection is allowed.  Currently,
// that authorization checks:
// * the hasn't expired based on the session.Expiration
// * number of connections already created is less than session.ConnectionLimit
// If authorization is success, it creates/stores a new connection in the repo
// and returns it, along with its states.  If the authorization fails, it
// an error with Code InvalidSessionState.
func (r *ConnectionRepository) AuthorizeConnection(ctx context.Context, sessionId, workerId string) (*Connection, error) {
	const op = "session.(ConnectionRepository).AuthorizeConnection"
	if sessionId == "" {
		return nil, errors.Wrap(ctx, status.Error(codes.FailedPrecondition, "missing session id"), op, errors.WithCode(errors.InvalidParameter))
	}
	connectionId, err := newConnectionId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	connection := AllocConnection()
	connection.PublicId = connectionId
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(ctx, authorizeConnectionCte, []any{
				sql.Named("session_id", sessionId),
				sql.Named("public_id", connectionId),
				sql.Named("worker_id", workerId),
			})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to authorize connection %s", sessionId)))
			}
			if rowsAffected == 0 {
				return errors.Wrap(ctx, status.Errorf(codes.PermissionDenied, "session %s is not authorized (not active, expired or connection limit reached)", sessionId), op, errors.WithCode(errors.InvalidSessionState))
			}
			if err := reader.LookupById(ctx, &connection); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for session %s", sessionId)))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return &connection, nil
}

// LookupConnection will look up a connection in the repository and return the connection
// with its state. If the connection is not found, it will return nil, nil.
// No options are currently supported.
func (r *ConnectionRepository) LookupConnection(ctx context.Context, connectionId string, _ ...Option) (*Connection, error) {
	const op = "session.(ConnectionRepository).LookupConnection"
	if connectionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing connectionId id")
	}
	connection := AllocConnection()
	connection.PublicId = connectionId
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &connection); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", connectionId)))
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return &connection, nil
}

// ListConnectionsBySessionId will list connections by session ID. Supports the
// WithLimit and WithOrder options.
func (r *ConnectionRepository) ListConnectionsBySessionId(ctx context.Context, sessionId string, opt ...Option) ([]*Connection, error) {
	const op = "session.(ConnectionRepository).ListConnectionsBySessionId"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no session ID supplied")
	}
	var connections []*Connection
	err := r.list(ctx, &connections, "session_id = ?", []any{sessionId}, opt...) // pass options, so WithLimit and WithOrder are supported
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return connections, nil
}

// ConnectConnection updates a connection in the repo with a state of "connected".
func (r *ConnectionRepository) ConnectConnection(ctx context.Context, c ConnectWith) (*Connection, error) {
	const op = "session.(ConnectionRepository).ConnectConnection"
	// ConnectWith.validate will check all the fields...
	if err := c.validate(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var connection Connection
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			connection = AllocConnection()
			connection.PublicId = c.ConnectionId
			connection.ClientTcpAddress = c.ClientTcpAddress
			connection.ClientTcpPort = c.ClientTcpPort
			connection.EndpointTcpAddress = c.EndpointTcpAddress
			connection.EndpointTcpPort = c.EndpointTcpPort
			connection.UserClientIp = c.UserClientIp
			fieldMask := []string{
				"ClientTcpAddress",
				"ClientTcpPort",
				"EndpointTcpAddress",
				"EndpointTcpPort",
				"UserClientIp",
			}
			rowsUpdated, err := w.Update(ctx, &connection, fieldMask, nil)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			// Set the lower bound of the connected_time_range to indicate the connection is connected
			rowsUpdated, err = w.Exec(ctx, connectConnection, []any{
				sql.Named("public_id", c.ConnectionId),
			})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated != 1 {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to connect connection %s", c.ConnectionId)))
			}
			if err := reader.LookupById(ctx, &connection); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for connection %s", c.ConnectionId)))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &connection, nil
}

// closeConnectionResp is just a wrapper for the response from CloseConnections.
// It wraps the connection and its state for each connection closed.
type closeConnectionResp struct {
	Connection      *Connection
	ConnectionState ConnectionStatus
}

// closeConnections set's a connection's state to "closed" in the repo.  It's
// called by a worker after it's closed a connection between the client and the
// endpoint
func (r *ConnectionRepository) closeConnections(ctx context.Context, closeWith []CloseWith, _ ...Option) ([]closeConnectionResp, error) {
	const op = "session.(ConnectionRepository).closeConnections"
	if len(closeWith) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing connections")
	}
	for _, cw := range closeWith {
		if err := cw.validate(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("%s was invalid", cw.ConnectionId)))
		}
	}
	var resp []closeConnectionResp
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			for _, cw := range closeWith {
				updateConnection := AllocConnection()
				updateConnection.PublicId = cw.ConnectionId
				updateConnection.BytesUp = cw.BytesUp
				updateConnection.BytesDown = cw.BytesDown
				updateConnection.ClosedReason = cw.ClosedReason.String()
				// updating the ClosedReason will trigger the session_connection to set the
				// upper limit of connection_time_range to indicate the connection is closed.
				rowsUpdated, err := w.Update(
					ctx,
					&updateConnection,
					[]string{"BytesUp", "BytesDown", "ClosedReason"},
					nil,
				)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to update connection %s", cw.ConnectionId)))
				}
				if rowsUpdated != 1 {
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("%d would have been updated for connection %s", rowsUpdated, cw.ConnectionId))
				}
				resp = append(resp, closeConnectionResp{
					Connection:      &updateConnection,
					ConnectionState: StatusClosed,
				})

			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return resp, nil
}

// DeleteConnection will delete a connection from the repository.
func (r *ConnectionRepository) DeleteConnection(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "session.(ConnectionRepository).DeleteConnection"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	connection := AllocConnection()
	connection.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &connection); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
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
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	return rowsDeleted, nil
}

// closeOrphanedConnections looks for connections that are still active, but were not reported by the worker.
func (r *ConnectionRepository) closeOrphanedConnections(ctx context.Context, workerId string, reportedConnections []string) ([]string, error) {
	const op = "session.(ConnectionRepository).closeOrphanedConnections"

	var orphanedConns []string

	args := make([]any, 0, len(reportedConnections)+2)
	args = append(args, sql.Named("worker_id", workerId))
	args = append(args, sql.Named("worker_state_delay_seconds", r.workerStateDelay.Seconds()))

	var notInClause string
	if len(reportedConnections) > 0 {
		notInClause = `and public_id not in (%s)`
		params := make([]string, len(reportedConnections))
		for i, connId := range reportedConnections {
			params[i] = fmt.Sprintf("@%d", i)
			args = append(args, sql.Named(fmt.Sprintf("%d", i), connId))
		}
		notInClause = fmt.Sprintf(notInClause, strings.Join(params, ","))
	}

	query := fmt.Sprintf(closeOrphanedConnections, notInClause)
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, query, args)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			for rows.Next() {
				var connectionId string
				if err := rows.Scan(&connectionId); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
				}
				orphanedConns = append(orphanedConns, connectionId)
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error getting next row"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error comparing state"))
	}
	return orphanedConns, nil
}
