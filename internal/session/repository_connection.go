package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/servers"
)

// deadWorkerConnCloseMinGrace is the minimum allowable setting for
// the CloseConnectionsForDeadWorkers method. This is synced with
// the default server liveness setting.
var DeadWorkerConnCloseMinGrace = int(servers.DefaultLiveness.Seconds())

// LookupConnection will look up a connection in the repository and return the connection
// with its states. If the connection is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *Repository) LookupConnection(ctx context.Context, connectionId string, _ ...Option) (*Connection, []*ConnectionState, error) {
	const op = "session.(Repository).LookupConnection"
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
func (r *Repository) ListConnectionsBySessionId(ctx context.Context, sessionId string, opt ...Option) ([]*Connection, error) {
	const op = "session.(Repository).ListConnectionsBySessionId"
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

// DeleteConnection will delete a connection from the repository.
func (r *Repository) DeleteConnection(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "session.(Repository).DeleteConnection"
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
func (r *Repository) CloseDeadConnectionsForWorker(ctx context.Context, serverId string, foundConns []string) (int, error) {
	const op = "session.(Repository).CloseDeadConnectionsForWorker"
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
			params[i] = fmt.Sprintf("$%d", i+2) // Add one for server ID, and offsets start at 1
			args = append(args, connId)
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
func (r *Repository) CloseConnectionsForDeadWorkers(ctx context.Context, gracePeriod int) ([]CloseConnectionsForDeadWorkersResult, error) {
	const op = "session.(Repository).CloseConnectionsForDeadWorkers"
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
				if err := w.ScanRows(rows, &result); err != nil {
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
func (r *Repository) ShouldCloseConnectionsOnWorker(ctx context.Context, foundConns, filterSessions []string) (map[string][]string, error) {
	const op = "session.(Repository).ShouldCloseConnectionsOnWorker"
	if len(foundConns) < 1 {
		return nil, nil // nothing to do
	}

	args := make([]interface{}, 0, len(foundConns)+len(filterSessions))

	// foundConns first
	connsParams := make([]string, len(foundConns))
	for i, connId := range foundConns {
		connsParams[i] = fmt.Sprintf("$%d", i+1)
		args = append(args, connId)
	}
	connsStr := strings.Join(connsParams, ",")

	// then filterSessions
	var sessionsStr string
	if len(filterSessions) > 0 {
		offset := len(foundConns) + 1
		sessionsParams := make([]string, len(filterSessions))
		for i, sessionId := range filterSessions {
			sessionsParams[i] = fmt.Sprintf("$%d", i+offset)
			args = append(args, sessionId)
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
