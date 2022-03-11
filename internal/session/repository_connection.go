package session

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/kms"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/servers"
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
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
	}, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit.  Supports WithOrder option.
func (r *ConnectionRepository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
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

// AuthorizeConnection will check to see if a connection is allowed.  Currently,
// that authorization checks:
// * the hasn't expired based on the session.Expiration
// * number of connections already created is less than session.ConnectionLimit
// If authorization is success, it creates/stores a new connection in the repo
// and returns it, along with its states.  If the authorization fails, it
// an error with Code InvalidSessionState.
func (r *ConnectionRepository) AuthorizeConnection(ctx context.Context, sessionId, workerId string) (*Connection, []*ConnectionState, error) {
	const op = "session.(ConnectionRepository).AuthorizeConnection"
	if sessionId == "" {
		return nil, nil, errors.Wrap(ctx, status.Error(codes.FailedPrecondition, "missing session id"), op, errors.WithCode(errors.InvalidParameter))
	}
	connectionId, err := newConnectionId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	connection := AllocConnection()
	connection.PublicId = connectionId
	var connectionStates []*ConnectionState
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(ctx, authorizeConnectionCte, []interface{}{
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
			connectionStates, err = fetchConnectionStates(ctx, reader, connectionId, db.WithOrder("start_time desc"))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return &connection, connectionStates, nil
}

// deadWorkerConnCloseMinGrace is the minimum allowable setting for
// the CloseConnectionsForDeadWorkers method. This is synced with
// the default server liveness setting.
var DeadWorkerConnCloseMinGrace = int(servers.DefaultLiveness.Seconds())

// LookupConnection will look up a connection in the repository and return the connection
// with its states. If the connection is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *ConnectionRepository) LookupConnection(ctx context.Context, connectionId string, _ ...Option) (*Connection, []*ConnectionState, error) {
	const op = "session.(ConnectionRepository).LookupConnection"
	if connectionId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing connectionId id")
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
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", connectionId)))
			}
			var err error
			if states, err = fetchConnectionStates(ctx, read, connectionId, db.WithOrder("start_time desc")); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil
		}
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return &connection, states, nil
}

// ListConnectionsBySessionId will list connections by session ID. Supports the
// WithLimit and WithOrder options.
func (r *ConnectionRepository) ListConnectionsBySessionId(ctx context.Context, sessionId string, opt ...Option) ([]*Connection, error) {
	const op = "session.(ConnectionRepository).ListConnectionsBySessionId"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no session ID supplied")
	}
	var connections []*Connection
	err := r.list(ctx, &connections, "session_id = ?", []interface{}{sessionId}, opt...) // pass options, so WithLimit and WithOrder are supported
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return connections, nil
}

// ConnectConnection updates a connection in the repo with a state of "connected".
func (r *ConnectionRepository) ConnectConnection(ctx context.Context, c ConnectWith) (*Connection, []*ConnectionState, error) {
	const op = "session.(ConnectionRepository).ConnectConnection"
	// ConnectWith.validate will check all the fields...
	if err := c.validate(); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	var connection Connection
	var connectionStates []*ConnectionState
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
			newState, err := NewConnectionState(connection.PublicId, StatusConnected)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if err := w.Create(ctx, newState); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			connectionStates, err = fetchConnectionStates(ctx, reader, c.ConnectionId, db.WithOrder("start_time desc"))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return &connection, connectionStates, nil
}

// closeConnectionResp is just a wrapper for the response from CloseConnections.
// It wraps the connection and its states for each connection closed.
type closeConnectionResp struct {
	Connection       *Connection
	ConnectionStates []*ConnectionState
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
		if err := cw.validate(); err != nil {
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
				// updating the ClosedReason will trigger an insert into the
				// session_connection_state with a state of closed.
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
				states, err := fetchConnectionStates(ctx, reader, cw.ConnectionId, db.WithOrder("start_time desc"))
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				resp = append(resp, closeConnectionResp{
					Connection:       &updateConnection,
					ConnectionStates: states,
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

// CloseDeadConnectionsForWorker will run closeDeadConnectionsCte to look for
// connections that should be marked closed because they are no longer claimed
// by a server.
//
// The foundConns input should be the currently-claimed connections; the CTE
// uses a NOT IN clause to ensure these are excluded. It is not an error for
// this to be empty as the worker could claim no connections; in that case all
// connections will immediately transition to closed.
func (r *ConnectionRepository) CloseDeadConnectionsForWorker(ctx context.Context, serverId string, foundConns []string) (int, error) {
	const op = "session.(ConnectionRepository).CloseDeadConnectionsForWorker"
	if serverId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing server id")
	}

	args := make([]interface{}, 0, len(foundConns)+1)
	args = append(args, serverId)

	var publicIdStr string
	if len(foundConns) > 0 {
		publicIdStr = `public_id not in (%s) and`
		params := make([]string, len(foundConns))
		for i, connId := range foundConns {
			params[i] = fmt.Sprintf("@%d", i+2) // Add one for server ID, and offsets start at 1
			args = append(args, sql.Named(fmt.Sprintf("%d", i+2), connId))
		}
		publicIdStr = fmt.Sprintf(publicIdStr, strings.Join(params, ","))
	}
	var rowsAffected int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			rowsAffected, err = w.Exec(ctx, fmt.Sprintf(closeDeadConnectionsCte, publicIdStr), args)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return rowsAffected, nil
}

type CloseConnectionsForDeadWorkersResult struct {
	ServerId                string
	LastUpdateTime          time.Time
	NumberConnectionsClosed int
}

// CloseConnectionsForDeadWorkers will run
// closeConnectionsForDeadServersCte to look for connections that
// should be marked because they are on a server that is no longer
// sending status updates to the controller(s).
//
// The only input to the method is the grace period, in seconds.
func (r *ConnectionRepository) CloseConnectionsForDeadWorkers(ctx context.Context, gracePeriod int) ([]CloseConnectionsForDeadWorkersResult, error) {
	const op = "session.(ConnectionRepository).CloseConnectionsForDeadWorkers"
	if gracePeriod < DeadWorkerConnCloseMinGrace {
		return nil, errors.New(ctx,
			errors.InvalidParameter, op, fmt.Sprintf("gracePeriod must be at least %d seconds", DeadWorkerConnCloseMinGrace))
	}

	results := make([]CloseConnectionsForDeadWorkersResult, 0)
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, closeConnectionsForDeadServersCte, []interface{}{gracePeriod})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			for rows.Next() {
				var result CloseConnectionsForDeadWorkersResult
				if err := w.ScanRows(ctx, rows, &result); err != nil {
					return errors.Wrap(ctx, err, op)
				}

				results = append(results, result)
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return results, nil
}

// ShouldCloseConnectionsOnWorker will run shouldCloseConnectionsCte to look
// for connections that the worker should close because they are currently
// reporting them as open incorrectly.
//
// The foundConns input here is used to filter closed connection states. This
// is further filtered against the filterSessions input, which is expected to
// be a set of sessions we've already submitted close requests for, so adding
// them again would be redundant.
//
// The returned map[string][]string is indexed by session ID.
func (r *ConnectionRepository) ShouldCloseConnectionsOnWorker(ctx context.Context, foundConns, filterSessions []string) (map[string][]string, error) {
	const op = "session.(ConnectionRepository).ShouldCloseConnectionsOnWorker"
	if len(foundConns) < 1 {
		return nil, nil // nothing to do
	}

	args := make([]interface{}, 0, len(foundConns)+len(filterSessions))

	// foundConns first
	connsParams := make([]string, len(foundConns))
	for i, connId := range foundConns {
		connsParams[i] = fmt.Sprintf("@%d", i+1)
		args = append(args, sql.Named(fmt.Sprintf("%d", i+1), connId))
	}
	connsStr := strings.Join(connsParams, ",")

	// then filterSessions
	var sessionsStr string
	if len(filterSessions) > 0 {
		offset := len(foundConns) + 1
		sessionsParams := make([]string, len(filterSessions))
		for i, sessionId := range filterSessions {
			sessionsParams[i] = fmt.Sprintf("@%d", i+offset)
			args = append(args, sql.Named(fmt.Sprintf("%d", i+offset), sessionId))
		}

		const sessionIdFmtStr = `and session_id not in (%s)`
		sessionsStr = fmt.Sprintf(sessionIdFmtStr, strings.Join(sessionsParams, ","))
	}

	rows, err := r.reader.Query(
		ctx,
		fmt.Sprintf(shouldCloseConnectionsCte, connsStr, sessionsStr),
		args,
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var connectionId, sessionId string
		if err := rows.Scan(&connectionId, &sessionId); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		result[sessionId] = append(result[sessionId], connectionId)
	}

	return result, nil
}

func fetchConnectionStates(ctx context.Context, r db.Reader, connectionId string, opt ...db.Option) ([]*ConnectionState, error) {
	const op = "session.fetchConnectionStates"
	var states []*ConnectionState
	if err := r.SearchWhere(ctx, &states, "connection_id = ?", []interface{}{connectionId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(states) == 0 {
		return nil, nil
	}
	return states, nil
}
