package session

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateSession inserts into the repository and returns the new Session with
// its State of "Pending".  The following fields must be empty when creating a
// session: ServerId, ServerType, and PublicId.  No options are
// currently supported.
func (r *Repository) CreateSession(ctx context.Context, sessionWrapper wrapping.Wrapper, newSession *Session, opt ...Option) (*Session, ed25519.PrivateKey, error) {
	if newSession == nil {
		return nil, nil, fmt.Errorf("create session: missing session: %w", db.ErrInvalidParameter)
	}
	if newSession.PublicId != "" {
		return nil, nil, fmt.Errorf("create session: public id is not empty: %w", db.ErrInvalidParameter)
	}
	if len(newSession.Certificate) != 0 {
		return nil, nil, fmt.Errorf("create session: certificate is not empty: %w", db.ErrInvalidParameter)
	}
	if newSession.TargetId == "" {
		return nil, nil, fmt.Errorf("create session: target id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.HostId == "" {
		return nil, nil, fmt.Errorf("create session: user id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.UserId == "" {
		return nil, nil, fmt.Errorf("create session: user id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.HostSetId == "" {
		return nil, nil, fmt.Errorf("create session: host set id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.AuthTokenId == "" {
		return nil, nil, fmt.Errorf("create session: auth token id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ScopeId == "" {
		return nil, nil, fmt.Errorf("create session: scope id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ServerId != "" {
		return nil, nil, fmt.Errorf("create session: server id must be empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ServerType != "" {
		return nil, nil, fmt.Errorf("create session: server type must be empty: %w", db.ErrInvalidParameter)
	}
	if newSession.CtTofuToken != nil {
		return nil, nil, fmt.Errorf("create session: ct must be empty: %w", db.ErrInvalidParameter)
	}
	if newSession.TofuToken != nil {
		return nil, nil, fmt.Errorf("create session: tofu token must be empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ExpirationTime == nil || newSession.ExpirationTime.Timestamp.AsTime().IsZero() {
		return nil, nil, fmt.Errorf("create session: expiration is empty: %w", db.ErrInvalidParameter)
	}

	id, err := newId()
	if err != nil {
		return nil, nil, fmt.Errorf("create session: %w", err)
	}

	privKey, certBytes, err := newCert(sessionWrapper, newSession.UserId, id, newSession.ExpirationTime.Timestamp.AsTime())
	if err != nil {
		return nil, nil, fmt.Errorf("create session: %w", err)
	}
	newSession.Certificate = certBytes
	newSession.PublicId = id

	var returnedSession *Session
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			returnedSession = newSession.Clone().(*Session)
			if err = w.Create(ctx, returnedSession); err != nil {
				return err
			}
			var foundStates []*State
			// trigger will create new "Pending" state
			if foundStates, err = fetchStates(ctx, read, returnedSession.PublicId); err != nil {
				return err
			}
			if len(foundStates) != 1 {
				return fmt.Errorf("%d states found for new session %s", len(foundStates), returnedSession.PublicId)
			}
			if len(foundStates) == 0 {
				return fmt.Errorf("no states found for new session %s", returnedSession.PublicId)
			}
			returnedSession.States = foundStates
			if returnedSession.States[0].Status != StatusPending {
				return fmt.Errorf("new session %s state is not valid: %s", returnedSession.PublicId, returnedSession.States[0].Status)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create session: %w", err)
	}
	return returnedSession, privKey, err
}

// LookupSession will look up a session in the repository and return the session
// with its states.  Returned States are ordered by start time descending.  If the
// session is not found, it will return nil, nil, nil. No options are currently
// supported.
func (r *Repository) LookupSession(ctx context.Context, sessionId string, opt ...Option) (*Session, *ConnectionAuthzSummary, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("lookup session: missing sessionId id: %w", db.ErrInvalidParameter)
	}
	session := AllocSession()
	session.PublicId = sessionId
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &session); err != nil {
				return fmt.Errorf("lookup session: failed %w for %s", err, sessionId)
			}
			states, err := fetchStates(ctx, read, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			session.States = states
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("lookup session: %w", err)
	}
	if len(session.CtTofuToken) > 0 {
		databaseWrapper, err := r.kms.GetWrapper(ctx, session.ScopeId, kms.KeyPurposeDatabase, kms.WithKeyId(session.KeyId))
		if err != nil {
			return nil, nil, fmt.Errorf("lookup session: unable to get database wrapper: %w", err)
		}
		if err := session.decrypt(ctx, databaseWrapper); err != nil {
			return nil, nil, fmt.Errorf("lookup session: cannot decrypt session value: %w", err)
		}
	} else {
		session.CtTofuToken = nil
	}

	authzSummary, err := r.sessionAuthzSummary(ctx, sessionId)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup session: failed to get authz summary: %w", err)
	}

	return &session, authzSummary, nil
}

// ListSessions will sessions.  Supports the WithLimit, WithScopeId and WithSessionIds options.
func (r *Repository) ListSessions(ctx context.Context, opt ...Option) ([]*Session, error) {
	opts := getOpts(opt...)
	var where []string
	var args []interface{}

	inClauseCnt := 0
	switch {
	case opts.withScopeId != "":
		inClauseCnt += 1
		where, args = append(where, fmt.Sprintf("scope_id = $%d", inClauseCnt)), append(args, opts.withScopeId)
	case opts.withUserId != "":
		inClauseCnt += 1
		where, args = append(where, fmt.Sprintf("user_id = $%d", inClauseCnt)), append(args, opts.withUserId)
	}
	if len(opts.withSessionIds) > 0 {
		idsInClause := make([]string, 0, len(opts.withSessionIds))
		for _, id := range opts.withSessionIds {
			inClauseCnt += 1
			idsInClause, args = append(idsInClause, fmt.Sprintf("$%d", inClauseCnt)), append(args, id)
		}
		where = append(where, fmt.Sprintf("s.public_id in(%s)", strings.Join(idsInClause, ",")))
	}

	var limit string
	switch {
	case opts.withLimit < 0: // any negative number signals unlimited results
	case opts.withLimit == 0: // zero signals the default value and default limits
		limit = fmt.Sprintf("limit %d", r.defaultLimit)
	default:
		// non-zero signals an override of the default limit for the repo.
		limit = fmt.Sprintf("limit %d", opts.withLimit)
	}

	if opts.withOrder != "" {
		opts.withOrder = fmt.Sprintf("order by %s", opts.withOrder)
	}

	var whereClause string
	if len(where) > 0 {
		whereClause = " and " + strings.Join(where, " and")
	}
	q := sessionList
	query := fmt.Sprintf(q, limit, whereClause, opts.withOrder)

	rows, err := r.reader.Query(ctx, query, args)
	if err != nil {
		return nil, fmt.Errorf("changes: query failed: %w", err)
	}
	defer rows.Close()

	var sessionsWithState []*sessionView
	for rows.Next() {
		var s sessionView
		if err := r.reader.ScanRows(rows, &s); err != nil {
			return nil, fmt.Errorf("changes: scan row failed: %w", err)
		}
		sessionsWithState = append(sessionsWithState, &s)
	}
	sessions, err := r.convertToSessions(ctx, sessionsWithState, withListingConvert(true))
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
}

// DeleteSession will delete a session from the repository.
func (r *Repository) DeleteSession(ctx context.Context, publicId string, opt ...Option) (int, error) {
	if publicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete session: missing public id %w", db.ErrInvalidParameter)
	}
	session := AllocSession()
	session.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &session); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete session: failed %w for %s", err, publicId)
	}

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteSession := session.Clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteSession,
			)
			if err == nil && rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return errors.New("error more than 1 session would have been deleted")
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete session: failed %w for %s", err, publicId)
	}
	return rowsDeleted, nil
}

// CancelSession sets a session's state to "canceling" in the repo.  It's called
// when the user cancels a session and the controller wants to update the
// session state to "canceling" for the given reason, so the workers can get the
// "canceling signal" during their next status heartbeat. CancelSession is
// idempotent.
func (r *Repository) CancelSession(ctx context.Context, sessionId string, sessionVersion uint32) (*Session, error) {
	if sessionId == "" {
		return nil, fmt.Errorf("cancel session: missing session id: %w", db.ErrInvalidParameter)
	}
	if sessionVersion == 0 {
		return nil, fmt.Errorf("cancel session: missing session version: %w", db.ErrInvalidParameter)
	}
	s, ss, err := r.updateState(ctx, sessionId, sessionVersion, StatusCanceling)
	if err != nil {
		return nil, fmt.Errorf("cancel session: %w", err)
	}
	s.States = ss
	return s, nil
}

// TerminateSession sets a session's termination reason and it's state to
// "terminated" Sessions cannot be terminated which still have connections that
// are not closed.
func (r *Repository) TerminateSession(ctx context.Context, sessionId string, sessionVersion uint32, reason TerminationReason) (*Session, error) {
	if sessionId == "" {
		return nil, fmt.Errorf("terminate session: missing session id: %w", db.ErrInvalidParameter)
	}
	if sessionVersion == 0 {
		return nil, fmt.Errorf("terminate session: version cannot be zero: %w", db.ErrInvalidParameter)
	}

	updatedSession := AllocSession()
	updatedSession.PublicId = sessionId
	updatedSession.TerminationReason = reason.String()
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(ctx, terminateSessionCte, []interface{}{sessionId, sessionVersion})
			if err != nil {
				return fmt.Errorf("unable to terminate session %s: %w", sessionId, err)
			}
			if rowsAffected == 0 {
				return fmt.Errorf("unable to terminate session %s", sessionId)
			}
			rowsUpdated, err := w.Update(ctx, &updatedSession, []string{"TerminationReason"}, nil, db.WithVersion(&sessionVersion))
			if err != nil {
				return fmt.Errorf("update session: failed %w for %s", err, sessionId)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("update to session %s would have updated %d session", updatedSession.PublicId, rowsUpdated)
			}
			states, err := fetchStates(ctx, reader, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			updatedSession.States = states
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("terminate session: %w", err)
	}
	return &updatedSession, nil
}

// TerminateCompletedSessions will terminate sessions in the repo based on:
//  * sessions that have exhausted their connection limit and all their connections are closed.
//	* sessions that are expired and all their connections are closed.
//	* sessions that are canceling and all their connections are closed
// This function should called on a periodic basis a Controllers via it's
// "ticker" pattern.
func (r *Repository) TerminateCompletedSessions(ctx context.Context) (int, error) {
	var rowsAffected int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			rowsAffected, err = w.Exec(ctx, termSessionsUpdate, nil)
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("terminate completed sessions: %w", err)
	}
	return rowsAffected, nil
}

// AuthorizeConnection will check to see if a connection is allowed.  Currently,
// that authorization checks:
// * the hasn't expired based on the session.Expiration
// * number of connections already created is less than session.ConnectionLimit
// If authorization is success, it creates/stores a new connection in the repo
// and returns it, along with it's states.  If the authorization fails, it
// an error of ErrInvalidStateForOperation.
func (r *Repository) AuthorizeConnection(ctx context.Context, sessionId string) (*Connection, []*ConnectionState, *ConnectionAuthzSummary, error) {
	if sessionId == "" {
		return nil, nil, nil, status.Errorf(codes.FailedPrecondition, "authorize connection: missing session id: %v", db.ErrInvalidParameter)
	}
	connectionId, err := newConnectionId()
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "authorize connection: %v", err)
	}

	connection := AllocConnection()
	connection.PublicId = connectionId
	var connectionStates []*ConnectionState
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(ctx, authorizeConnectionCte, []interface{}{sessionId, connectionId})
			if err != nil {
				return status.Errorf(codes.Internal, "unable to authorize connection %s: %v", sessionId, err)
			}
			if rowsAffected == 0 {
				return status.Errorf(codes.PermissionDenied, "authorize connection: session %s is not authorized (not active, expired or connection limit reached): %v", sessionId, ErrInvalidStateForOperation)
			}
			if err := reader.LookupById(ctx, &connection); err != nil {
				return status.Errorf(codes.Internal, "authorize connection: failed for session %s: %v", sessionId, err)
			}
			connectionStates, err = fetchConnectionStates(ctx, reader, connectionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	authzSummary, err := r.sessionAuthzSummary(ctx, connection.SessionId)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authorize connection: %w", err)
	}
	return &connection, connectionStates, authzSummary, nil
}

type ConnectionAuthzSummary struct {
	ExpirationTime         *timestamp.Timestamp
	ConnectionLimit        int32
	CurrentConnectionCount uint32
}

func (r *Repository) sessionAuthzSummary(ctx context.Context, sessionId string) (*ConnectionAuthzSummary, error) {
	rows, err := r.reader.Query(ctx, remainingConnectionsCte, []interface{}{sessionId})
	if err != nil {
		return nil, fmt.Errorf("session summary: query failed: %w", err)
	}
	defer rows.Close()

	var info *ConnectionAuthzSummary
	for rows.Next() {
		if info != nil {
			return nil, fmt.Errorf("session summary: query returned more than one row")
		}
		info = &ConnectionAuthzSummary{}
		if err := r.reader.ScanRows(rows, info); err != nil {
			return nil, fmt.Errorf("session summary: scan row failed: %w", err)
		}
	}
	return info, nil
}

// ConnectConnection updates a connection in the repo with a state of "connected".
func (r *Repository) ConnectConnection(ctx context.Context, c ConnectWith) (*Connection, []*ConnectionState, error) {
	// ConnectWith.validate will check all the fields...
	if err := c.validate(); err != nil {
		return nil, nil, fmt.Errorf("connect session: %w", err)
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
			fieldMask := []string{
				"ClientTcpAddress",
				"ClientTcpPort",
				"EndpointTcpAddress",
				"EndpointTcpPort",
			}
			rowsUpdated, err := w.Update(ctx, &connection, fieldMask, nil)
			if err != nil {
				return err
			}
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New("error more than 1 connection would have been updated ")
			}
			newState, err := NewConnectionState(connection.PublicId, StatusConnected)
			if err != nil {
				return err
			}
			if err := w.Create(ctx, newState); err != nil {
				return err
			}
			connectionStates, err = fetchConnectionStates(ctx, reader, c.ConnectionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("connect session: %w", err)
	}
	return &connection, connectionStates, nil
}

// CloseConnectionRep is just a wrapper for the response from CloseConnections.
// It wraps the connection and its states for each connection closed.
type CloseConnectionResp struct {
	Connection       *Connection
	ConnectionStates []*ConnectionState
}

// CloseConnections set's a connection's state to "closed" in the repo.  It's
// called by a worker after it's closed a connection between the client and the
// endpoint
func (r *Repository) CloseConnections(ctx context.Context, closeWith []CloseWith, opt ...Option) ([]CloseConnectionResp, error) {
	if len(closeWith) == 0 {
		return nil, fmt.Errorf("close connections: missing connections to close: %w", db.ErrInvalidParameter)
	}
	for _, cw := range closeWith {
		if err := cw.validate(); err != nil {
			return nil, fmt.Errorf("close connections: %s was invalid: %w", cw.ConnectionId, err)
		}
	}
	var resp []CloseConnectionResp
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
					return fmt.Errorf("unable to update connection %s: %w", cw.ConnectionId, err)
				}
				if rowsUpdated != 1 {
					return fmt.Errorf("%d would have been updated for connection %s", rowsUpdated, cw.ConnectionId)
				}
				states, err := fetchConnectionStates(ctx, reader, cw.ConnectionId, db.WithOrder("start_time desc"))
				if err != nil {
					return err
				}
				resp = append(resp, CloseConnectionResp{
					Connection:       &updateConnection,
					ConnectionStates: states,
				})

			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("close connections: %w", err)
	}
	return resp, nil
}

// ActivateSession will activate the session and is called by a worker after
// authenticating the session. The session must be in a "pending" state to be
// activated. States are ordered by start time descending. Returns an
// ErrSessionNotPending error if a connection cannot be made because the session
// was canceled or terminated.
func (r *Repository) ActivateSession(ctx context.Context, sessionId string, sessionVersion uint32, serverId, serverType string, tofuToken []byte) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("activate session: missing session id: %w", db.ErrInvalidParameter)
	}
	if sessionVersion == 0 {
		return nil, nil, fmt.Errorf("activate session: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	if serverId == "" {
		return nil, nil, fmt.Errorf("activate session: missing server id: %w", db.ErrInvalidParameter)
	}
	if serverType == "" {
		return nil, nil, fmt.Errorf("activate session: missing server type: %w", db.ErrInvalidParameter)
	}
	if len(tofuToken) == 0 {
		return nil, nil, fmt.Errorf("activate session: missing tofu token: %w", db.ErrInvalidParameter)
	}

	updatedSession := AllocSession()
	updatedSession.PublicId = sessionId
	var returnedStates []*State
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(ctx, activateStateCte, []interface{}{sessionId, sessionVersion})
			if err != nil {
				return fmt.Errorf("unable to activate session %s: %w", sessionId, err)
			}
			if rowsAffected == 0 {
				return fmt.Errorf("unable to activate session %s: %w", sessionId, ErrSessionNotPending)
			}
			foundSession := AllocSession()
			foundSession.PublicId = sessionId
			if err := reader.LookupById(ctx, &foundSession); err != nil {
				return fmt.Errorf("lookup session: failed for %s: %w", sessionId, err)
			}
			databaseWrapper, err := r.kms.GetWrapper(ctx, foundSession.ScopeId, kms.KeyPurposeDatabase)
			if err != nil {
				return fmt.Errorf("unable to get database wrapper: %w", err)
			}
			if len(foundSession.TofuToken) > 0 && subtle.ConstantTimeCompare(foundSession.TofuToken, tofuToken) != 1 {
				return fmt.Errorf("tofu token mismatch")
			}

			updatedSession.TofuToken = tofuToken
			updatedSession.ServerId = serverId
			updatedSession.ServerType = serverType
			if err := updatedSession.encrypt(ctx, databaseWrapper); err != nil {
				return err
			}
			rowsUpdated, err := w.Update(ctx, &updatedSession, []string{"CtTofuToken"}, nil)
			if err != nil {
				return err
			}
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New("error more than 1 session would have been updated ")
			}

			returnedStates, err = fetchStates(ctx, reader, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("activate session: %w", err)
	}
	return &updatedSession, returnedStates, nil
}

// updateState will update the session's state using the session id and its
// version. updateState is idempotent. States are ordered by start time
// descending. No options are currently supported.
func (r *Repository) updateState(ctx context.Context, sessionId string, sessionVersion uint32, s Status, opt ...Option) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("update session state: missing session id %w", db.ErrInvalidParameter)
	}
	if sessionVersion == 0 {
		return nil, nil, fmt.Errorf("update session state: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	if s == "" {
		return nil, nil, fmt.Errorf("update session state: missing session status: %w", db.ErrInvalidParameter)
	}
	if s == StatusActive {
		return nil, nil, fmt.Errorf("update session: you must call ActivateSession to update a session's state to active: %w", db.ErrInvalidParameter)
	}

	var rowsAffected int
	updatedSession := AllocSession()
	var returnedStates []*State
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			// We need to update the session version as that's the aggregate
			updatedSession.PublicId = sessionId
			updatedSession.Version = uint32(sessionVersion) + 1
			rowsUpdated, err := w.Update(ctx, &updatedSession, []string{"Version"}, nil, db.WithVersion(&sessionVersion))
			if err != nil {
				return err
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("updated session and %d rows updated", rowsUpdated)
			}
			if len(updatedSession.CtTofuToken) > 0 {
				databaseWrapper, err := r.kms.GetWrapper(ctx, updatedSession.ScopeId, kms.KeyPurposeDatabase, kms.WithKeyId(updatedSession.KeyId))
				if err != nil {
					return fmt.Errorf("lookup session: unable to get database wrapper: %w", err)
				}
				if err := updatedSession.decrypt(ctx, databaseWrapper); err != nil {
					return fmt.Errorf("lookup session: cannot decrypt session value: %w", err)
				}
			} else {
				updatedSession.CtTofuToken = nil
			}

			rowsAffected, err = w.Exec(ctx, updateSessionState, []interface{}{sessionId, s.String()})
			if err != nil {
				return fmt.Errorf("unable to update session %s state to %s: %w", sessionId, s.String(), err)
			}
			if rowsAffected != 0 && rowsAffected != 1 {
				return fmt.Errorf("updated session %s to state %s and %d rows inserted (should be 0 or 1)", sessionId, s.String(), rowsAffected)
			}
			returnedStates, err = fetchStates(ctx, reader, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			if len(returnedStates) < 1 && returnedStates[0].Status != s {
				return fmt.Errorf("failed to update %s to a state of %s", sessionId, s.String())
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("update session state: error creating new state: %w", err)
	}
	return &updatedSession, returnedStates, nil
}

func fetchStates(ctx context.Context, r db.Reader, sessionId string, opt ...db.Option) ([]*State, error) {
	var states []*State
	if err := r.SearchWhere(ctx, &states, "session_id = ?", []interface{}{sessionId}, opt...); err != nil {
		return nil, fmt.Errorf("fetch session states: %w", err)
	}
	if len(states) == 0 {
		return nil, nil
	}
	return states, nil
}
