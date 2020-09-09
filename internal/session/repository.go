package session

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// Clonable provides a cloning interface
type Cloneable interface {
	Clone() interface{}
}

// Repository is the session database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new session Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if kms == nil {
		return nil, errors.New("error creating db repository with nil kms")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
	}, nil
}

// CreateSession inserts into the repository and returns the new Session with
// its State of "Pending".  The following fields must be empty when creating a
// session: Address, Port, ServerId, ServerType, and PublicId.  No options are
// currently supported.
func (r *Repository) CreateSession(ctx context.Context, newSession *Session, opt ...Option) (*Session, *State, error) {
	if newSession == nil {
		return nil, nil, fmt.Errorf("create session: missing session: %w", db.ErrInvalidParameter)
	}
	if newSession.Session == nil {
		return nil, nil, fmt.Errorf("create session: missing session store: %w", db.ErrInvalidParameter)
	}
	if newSession.PublicId != "" {
		return nil, nil, fmt.Errorf("create session: public id is not empty: %w", db.ErrInvalidParameter)
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
	if newSession.SetId == "" {
		return nil, nil, fmt.Errorf("create session: set id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.AuthTokenId == "" {
		return nil, nil, fmt.Errorf("create session: auth token id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ScopeId == "" {
		return nil, nil, fmt.Errorf("create session: scope id is empty: %w", db.ErrInvalidParameter)
	}
	if newSession.Address != "" {
		return nil, nil, fmt.Errorf("create session: address must empty: %w", db.ErrInvalidParameter)
	}
	if newSession.Port != "" {
		return nil, nil, fmt.Errorf("create session: port id must empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ServerId != "" {
		return nil, nil, fmt.Errorf("create session: server id must empty: %w", db.ErrInvalidParameter)
	}
	if newSession.ServerType != "" {
		return nil, nil, fmt.Errorf("create session: server type must empty: %w", db.ErrInvalidParameter)
	}

	id, err := newId()
	if err != nil {
		return nil, nil, fmt.Errorf("create session: %w", err)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, newSession.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, fmt.Errorf("create session: unable to get oplog wrapper: %w", err)
	}

	var returnedSession *Session
	var returnedState *State
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			returnedSession = newSession.Clone().(*Session)
			returnedSession.PublicId = id
			metadata := returnedSession.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err = w.Create(ctx, returnedSession, db.WithOplog(oplogWrapper, metadata)); err != nil {
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
		return nil, nil, fmt.Errorf("create session: %w", err)
	}
	return returnedSession, returnedState, err
}

// LookupSession will look up a session in the repository and return the session
// with its states.  If the session is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *Repository) LookupSession(ctx context.Context, sessionId string, opt ...Option) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("lookup session: missing sessionId id: %w", db.ErrInvalidParameter)
	}
	session := allocSession()
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
	return sessions, nil
}

// DeleteSession will delete a session from the repository.
func (r *Repository) DeleteSession(ctx context.Context, publicId string, opt ...Option) (int, error) {
	if publicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete session: missing public id %w", db.ErrInvalidParameter)
	}
	session := allocSession()
	session.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &session); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete session: failed %w for %s", err, publicId)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, session.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("unable to get oplog wrapper: %w", err)
	}
	metadata := session.oplog(oplog.OpType_OP_TYPE_DELETE)
	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteSession := session.Clone()
			rowsDeleted, err = w.Delete(
				ctx,
				deleteSession,
				db.WithOplog(oplogWrapper, metadata),
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

// UpdateSession updates the repository entry for the session, using the
// fieldMaskPaths.  Only BytesUp, BytesDown, TerminationReason, ServerId and
// ServerType a muttable and will be set to NULL if set to a zero value and
// included in the fieldMaskPaths.
func (r *Repository) UpdateSession(ctx context.Context, session *Session, version uint32, fieldMaskPaths []string, opt ...Option) (*Session, []*State, int, error) {
	if session == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: missing session %w", db.ErrInvalidParameter)
	}
	if session.Session == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: missing session store %w", db.ErrInvalidParameter)
	}
	if session.PublicId == "" {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: missing session public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("BytesUp", f):
		case strings.EqualFold("BytesDown", f):
		case strings.EqualFold("TerminationReason", f):
		case strings.EqualFold("ServerId", f):
		case strings.EqualFold("ServerType", f):
		case strings.EqualFold("Address", f):
		case strings.EqualFold("Port", f):
		default:
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"BytesUp":           session.BytesUp,
			"BytesDown":         session.BytesDown,
			"TerminationReason": session.TerminationReason,
			"ServerId":          session.ServerId,
			"ServerType":        session.ServerType,
			"Address":           session.Address,
			"Port":              session.Port,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: %w", db.ErrEmptyFieldMask)
	}

	var sessionScopeId string
	switch {
	case session.ScopeId != "":
		sessionScopeId = session.ScopeId
	default:
		ses, _, err := r.LookupSession(ctx, session.PublicId)
		if err != nil {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: %w", err)
		}
		if ses == nil {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: unable to look up session for %s: %w", session.PublicId, err)
		}
		sessionScopeId = ses.ScopeId
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, sessionScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("unable to get oplog wrapper: %w", err)
	}

	var s *Session
	var states []*State
	var rowsUpdated int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			s = session.Clone().(*Session)
			metadata := s.oplog(oplog.OpType_OP_TYPE_UPDATE)
			metadata["scope-id"] = []string{sessionScopeId}
			rowsUpdated, err = w.Update(
				ctx,
				s,
				dbMask,
				nullFields,
				db.WithOplog(oplogWrapper, metadata),
			)
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New("error more than 1 session would have been updated ")
			}
			states, err = fetchStates(ctx, reader, s.PublicId, db.WithOrder("start_time desc"))
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: %w for %s", err, session.PublicId)
	}
	return s, states, rowsUpdated, err
}

// UpdateState will update the session's state using the session id and its
// version.  No options are currently supported.
func (r *Repository) UpdateState(ctx context.Context, sessionId string, sessionVersion uint32, s Status, opt ...Option) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("update session state: missing session id %w", db.ErrInvalidParameter)
	}
	if sessionVersion == 0 {
		return nil, nil, fmt.Errorf("update session state: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	if s == "" {
		return nil, nil, fmt.Errorf("update session state: missing session status: %w", db.ErrInvalidParameter)
	}

	newState, err := NewState(sessionId, s)
	if err != nil {
		return nil, nil, fmt.Errorf("update session state: %w", err)
	}
	ses, _, err := r.LookupSession(ctx, sessionId)
	if err != nil {
		return nil, nil, fmt.Errorf("update session state: %w", err)
	}
	if ses == nil {
		return nil, nil, fmt.Errorf("update session state: unable to look up session for %s: %w", sessionId, err)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, ses.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, fmt.Errorf("update session state: unable to get oplog wrapper: %w", err)
	}

	updatedSession := allocSession()
	var returnedStates []*State
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			sessionTicket, err := w.GetTicket(ses)
			if err != nil {
				return fmt.Errorf("unable to get ticket: %w", err)
			}

			// We need to update the session version as that's the aggregate
			updatedSession.PublicId = sessionId
			updatedSession.Version = uint32(sessionVersion) + 1
			var sessionOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, &updatedSession, []string{"Version"}, nil, db.NewOplogMsg(&sessionOplogMsg), db.WithVersion(&sessionVersion))
			if err != nil {
				return fmt.Errorf("unable to update session version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("updated session and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &sessionOplogMsg)
			var stateOplogMsg oplog.Message
			if err := w.Create(ctx, newState, db.NewOplogMsg(&stateOplogMsg)); err != nil {
				return fmt.Errorf("unable to add new state: %w", err)
			}
			msgs = append(msgs, &stateOplogMsg)

			metadata := oplog.Metadata{
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{ses.ScopeId},
				"scope-type":         []string{"project"},
				"resource-public-id": []string{sessionId},
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, sessionTicket, metadata, msgs); err != nil {
				return fmt.Errorf("unable to write oplog: %w", err)
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
	return &updatedSession, returnedStates, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit.  Supports WithOrder option.
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	if opts.withOrder != "" {
		dbOpts = append(dbOpts, db.WithOrder(opts.withOrder))
	}
	return r.reader.SearchWhere(ctx, resources, where, args, dbOpts...)
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
