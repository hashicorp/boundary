package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateSession inserts into the repository and returns the new Session with
// its State of "Pending".  The following fields must be empty when creating a
// session: ServerId, ServerType, and PublicId.  No options are
// currently supported.
func (r *Repository) CreateSession(ctx context.Context, sessionWrapper wrapping.Wrapper, newSession *Session, opt ...Option) (*Session, *State, ed25519.PrivateKey, error) {
	if newSession == nil {
		return nil, nil, nil, fmt.Errorf("create session: missing session: %w", db.ErrInvalidParameter)
	}
	if newSession.PublicId != "" {
		return nil, nil, nil, fmt.Errorf("create session: public id is not empty: %w", db.ErrInvalidParameter)
	}
	if len(newSession.Certificate) != 0 {
		return nil, nil, nil, fmt.Errorf("create session: certificate is not empty: %w", db.ErrInvalidParameter)
	}
	if newSession.TargetId == "" {
		return nil, nil, nil, fmt.Errorf("create session: target id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.HostId == "" {
		return nil, nil, nil, fmt.Errorf("create session: user id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.UserId == "" {
		return nil, nil, nil, fmt.Errorf("create session: user id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.HostSetId == "" {
		return nil, nil, nil, fmt.Errorf("create session: host set id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.AuthTokenId == "" {
		return nil, nil, nil, fmt.Errorf("create session: auth token id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ScopeId == "" {
		return nil, nil, nil, fmt.Errorf("create session: scope id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ServerId != "" {
		return nil, nil, nil, fmt.Errorf("create session: server id must empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ServerType != "" {
		return nil, nil, nil, fmt.Errorf("create session: server type must empty: %w", db.ErrInvalidParameter)
	}
	if newSession.CtTofuToken != nil {
		return nil, nil, nil, fmt.Errorf("create session: ct must be empty: %w", db.ErrInvalidParameter)
	}
	if newSession.TofuToken != nil {
		return nil, nil, nil, fmt.Errorf("create session: tofu token must be empty: %w", db.ErrInvalidParameter)
	}

	id, err := newId()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create session: %w", err)
	}

	privKey, certBytes, err := newCert(sessionWrapper, newSession.UserId, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create session: %w", err)
	}
	newSession.Certificate = certBytes
	newSession.PublicId = id

	var returnedSession *Session
	var returnedState *State
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
			returnedState = foundStates[0]
			if returnedState.Status != StatusPending.String() {
				return fmt.Errorf("new session %s state is not valid: %s", returnedSession.PublicId, returnedState.Status)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create session: %w", err)
	}
	return returnedSession, returnedState, privKey, err
}

// LookupSession will look up a session in the repository and return the session
// with its states.  Returned States are ordered by start time descending.  If the
// session is not found, it will return nil, nil, nil. No options are currently
// supported.
func (r *Repository) LookupSession(ctx context.Context, sessionId string, opt ...Option) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("lookup session: missing sessionId id: %w", db.ErrInvalidParameter)
	}
	session := AllocSession()
	session.PublicId = sessionId
	var states []*State
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &session); err != nil {
				return fmt.Errorf("lookup session: failed %w for %s", err, sessionId)
			}
			var err error
			if states, err = fetchStates(ctx, read, sessionId, db.WithOrder("start_time desc")); err != nil {
				return err
			}
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
	return &session, states, nil
}

// ListSessions will sessions.  Supports the WithLimit, WithScopeId and WithOrder options.
func (r *Repository) ListSessions(ctx context.Context, opt ...Option) ([]*Session, error) {
	opts := getOpts(opt...)
	var where []string
	var args []interface{}
	switch {
	case opts.withScopeId != "":
		where, args = append(where, "scope_id = ?"), append(args, opts.withScopeId)
	case opts.withUserId != "":
		where, args = append(where, "user_id = ?"), append(args, opts.withUserId)
	}

	var sessions []*Session
	err := r.list(ctx, &sessions, strings.Join(where, " and"), args, opt...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	for _, s := range sessions {
		s.CtTofuToken = nil
		s.TofuToken = nil
		s.KeyId = ""
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

// CancelSession sets a session's state to "cancelling" in the repo.  It's
// called when the user cancels a session and the controller wants to update the
// session state to "cancelling" for the given reason, so the workers can get
// the "cancelling signal" during their next status heartbeat.
func (r *Repository) CancelSession(ctx context.Context, sessionId string, sessionVersion uint32) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("cancel session: missing session id: %w", db.ErrInvalidParameter)
	}
	if sessionVersion == 0 {
		return nil, nil, fmt.Errorf("cancel session: missing session version: %w", db.ErrInvalidParameter)
	}
	s, ss, err := r.updateState(ctx, sessionId, sessionVersion, StatusCancelling)
	if err != nil {
		return nil, nil, fmt.Errorf("cancel session: %w", err)
	}
	return s, ss, nil
}

// TerminateSession sets a session's state to "terminated" in the repo.  It's
// called by the worker when the session has been terminated or by a controller
// when all of a session's workers have stopped sending heartbeat status for a
// period of time.  Sessions cannot be terminated which still have connections
// that are not closed.
func (r *Repository) TerminateSession(ctx context.Context, sessionId string, sessionVersion uint32, reason TerminationReason) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("terminate session: missing session id: %w", db.ErrInvalidParameter)
	}
	if sessionVersion == 0 {
		return nil, nil, fmt.Errorf("terminate session: version cannot be zero: %w", db.ErrInvalidParameter)
	}

	updatedSession := AllocSession()
	updatedSession.PublicId = sessionId
	updatedSession.TerminationReason = reason.String()
	var returnedStates []*State
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(terminateSessionCte, []interface{}{sessionId, sessionVersion})
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
			returnedStates, err = fetchStates(ctx, reader, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("terminate session: %w", err)
	}
	return &updatedSession, returnedStates, nil
}

// ConnectSession creates a connection in the repo with a state of "connected".
// Returns an ErrCancelledOrTerminatedSession error if a connection cannot be made
// because the session was cancelled or terminated.
func (r *Repository) ConnectSession(ctx context.Context, c ConnectWith) (*Connection, []*ConnectionState, error) {
	// ConnectWith.validate will check all the fields...
	if err := c.validate(); err != nil {
		return nil, nil, fmt.Errorf("connect session: %w", err)
	}
	connectionId, err := newConnectionId()
	if err != nil {
		return nil, nil, fmt.Errorf("connect session: %w", err)
	}

	connection := AllocConnection()
	connection.PublicId = connectionId
	var connectionStates []*ConnectionState
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(createConnectionCte, []interface{}{c.SessionId, connectionId, c.ClientTcpAddress, c.ClientTcpPort, c.EndpointTcpAddress, c.EndpointTcpPort})
			if err != nil {
				return fmt.Errorf("unable to connect session %s: %w", c.SessionId, err)
			}
			if rowsAffected == 0 {
				return fmt.Errorf("session %s is not active: %w", c.SessionId, ErrInvalidStateForOperation)
			}
			if err := reader.LookupById(ctx, &connection); err != nil {
				return fmt.Errorf("lookup session: failed %w for %s", err, c.SessionId)
			}
			connectionStates, err = fetchConnectionStates(ctx, reader, connectionId, db.WithOrder("start_time desc"))
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
func (r *Repository) CloseConnections(ctx context.Context, closeWith []ClosedWith, opt ...Option) ([]CloseConnectionResp, error) {
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
				rowsUpdated, err := w.Update(
					ctx,
					&updateConnection,
					[]string{"BytesUp", "BytesDown", "ClosedReason"},
					nil,
					db.WithVersion(&cw.ConnectionVersion),
				)
				if err != nil {
					return fmt.Errorf("unable to update connection %s: %w", cw.ConnectionId, err)
				}
				if rowsUpdated != 1 {
					return fmt.Errorf("%d would have been updated for connection %s", rowsUpdated, cw.ConnectionId)
				}
				closedState, err := NewConnectionState(cw.ConnectionId, StatusClosed)
				if err != nil {
					return fmt.Errorf("connection %s: %w", cw.ConnectionId, err)
				}
				if err := w.Create(ctx, closedState); err != nil {
					return fmt.Errorf("connection %s: unable to add closed state: %w", cw.ConnectionId, err)
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
// was cancelled or terminated.
func (r *Repository) ActivateSession(ctx context.Context, sessionId string, sessionVersion uint32, serverId, serverType string, tofuToken []byte) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("activate session: missing session id %w", db.ErrInvalidParameter)
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
	updatedSession := AllocSession()
	updatedSession.PublicId = sessionId
	var returnedStates []*State
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(activateStateCte, []interface{}{sessionId, sessionVersion})
			if err != nil {
				return fmt.Errorf("unable to activate session %s: %w", sessionId, err)
			}
			if rowsAffected == 0 {
				return fmt.Errorf("unable to activate session %s: %w", sessionId, ErrSessionNotPending)
			}
			foundSession := AllocSession()
			foundSession.PublicId = sessionId
			if err := reader.LookupById(ctx, &foundSession); err != nil {
				return fmt.Errorf("lookup session: failed %w for %s", err, sessionId)
			}
			databaseWrapper, err := r.kms.GetWrapper(ctx, foundSession.ScopeId, kms.KeyPurposeDatabase)
			if err != nil {
				return fmt.Errorf("unable to get database wrapper: %w", err)
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
// version.  States are ordered by start time descending. No options are
// currently supported.
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

	newState, err := NewState(sessionId, s)
	if err != nil {
		return nil, nil, fmt.Errorf("update session state: %w", err)
	}

	updatedSession := AllocSession()
	var returnedStates []*State
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			// We need to update the session version as that's the aggregate
			updatedSession.PublicId = sessionId
			updatedSession.Version = uint32(sessionVersion) + 1
			rowsUpdated, err := w.Update(ctx, &updatedSession, []string{"Version"}, nil, db.WithVersion(&sessionVersion))
			if err != nil {
				return fmt.Errorf("unable to update session version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("updated session and %d rows updated", rowsUpdated)
			}
			if err := w.Create(ctx, newState); err != nil {
				return fmt.Errorf("unable to add new state: %w", err)
			}

			returnedStates, err = fetchStates(ctx, reader, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("update session state: error creating new state: %w", err)
	}
	if len(updatedSession.CtTofuToken) == 0 {
		updatedSession.CtTofuToken = nil
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
