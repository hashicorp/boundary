package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/vault/sdk/helper/strutil"
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

// UpdateSession updates the repository entry for the session, using the
// fieldMaskPaths.  Only TerminationReason, ServerId and ServerType a muttable
// and will be set to NULL if set to a zero value and included in the
// fieldMaskPaths. Returned States are ordered by start time descending.
func (r *Repository) UpdateSession(ctx context.Context, session *Session, version uint32, fieldMaskPaths []string, opt ...Option) (*Session, []*State, int, error) {
	if session == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: missing session %w", db.ErrInvalidParameter)
	}
	if session.PublicId == "" {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: missing session public id %w", db.ErrInvalidParameter)
	}
	if session.CtTofuToken != nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: ct must be empty: %w", db.ErrInvalidParameter)
	}

	translatedFieldMasks := make([]string, 0, len(fieldMaskPaths))
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("TerminationReason", f):
			translatedFieldMasks = append(translatedFieldMasks, f)
		case strings.EqualFold("ServerId", f):
			translatedFieldMasks = append(translatedFieldMasks, f)
		case strings.EqualFold("ServerType", f):
			translatedFieldMasks = append(translatedFieldMasks, f)
		case strings.EqualFold("TofuToken", f):
			translatedFieldMasks = append(translatedFieldMasks, "CtTofuToken")
		default:
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}

	updateSession := session.Clone().(*Session)
	if strutil.StrListContains(translatedFieldMasks, "CtTofuToken") && len(updateSession.TofuToken) != 0 {
		if err := r.reader.LookupById(ctx, updateSession); err != nil {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: %w for %s", err, updateSession.PublicId)
		}
		databaseWrapper, err := r.kms.GetWrapper(ctx, updateSession.ScopeId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: unable to get database wrapper: %w", err)
		}
		if err := updateSession.encrypt(ctx, databaseWrapper); err != nil {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("create session: %w", err)
		}
	}

	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"TerminationReason": updateSession.TerminationReason,
			"ServerId":          updateSession.ServerId,
			"ServerType":        updateSession.ServerType,
			"CtTofuToken":       updateSession.CtTofuToken,
		},
		translatedFieldMasks,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update session: %w", db.ErrEmptyFieldMask)
	}

	var s *Session
	var states []*State
	var rowsUpdated int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			s = updateSession.Clone().(*Session)

			rowsUpdated, err = w.Update(
				ctx,
				s,
				dbMask,
				nullFields,
			)
			if err != nil {
				return err
			}
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
	if len(s.CtTofuToken) == 0 {
		s.CtTofuToken = nil
	}
	return s, states, rowsUpdated, err
}

// ActivateSession will activate the session and is called by a worker after
// authenticating the session. States are ordered by start time descending.
func (r *Repository) ActivateSession(ctx context.Context, sessionId string, sessionVersion uint32, tofuToken []byte) (*Session, []*State, error) {
	if sessionId == "" {
		return nil, nil, fmt.Errorf("activate session state: missing session id %w", db.ErrInvalidParameter)
	}
	if sessionVersion == 0 {
		return nil, nil, fmt.Errorf("activate session state: version cannot be zero: %w", db.ErrInvalidParameter)
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
				return fmt.Errorf("unable to activate session %s", sessionId)
			}
			foundSession := AllocSession()
			foundSession.PublicId = sessionId
			if err := r.reader.LookupById(ctx, &foundSession); err != nil {
				return fmt.Errorf("lookup session: failed %w for %s", err, sessionId)
			}
			databaseWrapper, err := r.kms.GetWrapper(ctx, foundSession.ScopeId, kms.KeyPurposeDatabase)
			if err != nil {
				return fmt.Errorf("unable to get database wrapper: %w", err)
			}

			updatedSession.TofuToken = tofuToken
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

// UpdateState will update the session's state using the session id and its
// version.  States are ordered by start time descending. No options are
// currently supported.
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
