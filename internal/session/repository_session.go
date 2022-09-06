package session

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateSession inserts into the repository and returns the new Session with
// its State of "Pending".  The following fields must be empty when creating a
// session: WorkerId, and PublicId.  No options are
// currently supported.
func (r *Repository) CreateSession(ctx context.Context, sessionWrapper wrapping.Wrapper, newSession *Session, workerAddresses []string, _ ...Option) (*Session, ed25519.PrivateKey, error) {
	const op = "session.(Repository).CreateSession"
	if newSession == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing session")
	}
	if newSession.PublicId != "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "public id is not empty")
	}
	if len(newSession.Certificate) != 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "certificate is not empty")
	}
	if newSession.TargetId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if newSession.HostId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing host id")
	}
	if newSession.UserId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	if newSession.HostSetId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing host set id")
	}
	if newSession.AuthTokenId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token id")
	}
	if newSession.ProjectId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if newSession.CtTofuToken != nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "ct is not empty")
	}
	if newSession.TofuToken != nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "tofu token is not empty")
	}
	if newSession.ExpirationTime == nil || newSession.ExpirationTime.Timestamp.AsTime().IsZero() {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing expiration time")
	}
	if len(workerAddresses) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing addresses")
	}

	id, err := newId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	privKey, certBytes, err := newCert(ctx, sessionWrapper, newSession.UserId, id, workerAddresses, newSession.ExpirationTime.Timestamp.AsTime())
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	newSession.Certificate = certBytes
	newSession.PublicId = id
	newSession.KeyId, err = sessionWrapper.KeyId(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to get session wrapper key id"))
	}

	var returnedSession *Session
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			returnedSession = newSession.Clone().(*Session)
			returnedSession.DynamicCredentials = nil
			returnedSession.StaticCredentials = nil
			if err = w.Create(ctx, returnedSession); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			for _, cred := range newSession.DynamicCredentials {
				cred.SessionId = newSession.PublicId
			}

			var staticCreds []interface{}
			for _, cred := range newSession.StaticCredentials {
				cred.SessionId = newSession.PublicId
				staticCreds = append(staticCreds, cred)
			}

			if len(staticCreds) > 0 {
				if err = w.CreateItems(ctx, staticCreds); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("failed to create static credentials"))
				}

				// Get static creds back from the db for return
				var c []*StaticCredential
				if err := read.SearchWhere(ctx, &c, "session_id = ?", []interface{}{newSession.PublicId}); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				returnedSession.StaticCredentials = c
			}

			// TODO: after upgrading to gorm v2 this batch insert can be replaced, since gorm v2 supports batch inserts
			q, batchInsertArgs, err := batchInsertsessionCredentialDynamic(newSession.DynamicCredentials)
			if err == nil {
				rows, err := w.Query(ctx, q, batchInsertArgs)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				defer rows.Close()
				for rows.Next() {
					var returnedCred DynamicCredential
					w.ScanRows(ctx, rows, &returnedCred)
					returnedSession.DynamicCredentials = append(returnedSession.DynamicCredentials, &returnedCred)
				}
			}

			var foundStates []*State
			// trigger will create new "Pending" state
			if foundStates, err = fetchStates(ctx, read, returnedSession.PublicId); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if len(foundStates) == 0 {
				return errors.New(ctx, errors.SessionNotFound, op, fmt.Sprintf("no states found for new session %s", returnedSession.PublicId))
			}
			if len(foundStates) != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("%d states found for new session %s", len(foundStates), returnedSession.PublicId))
			}
			returnedSession.States = foundStates
			if returnedSession.States[0].Status != StatusPending {
				return errors.New(ctx, errors.InvalidSessionState, op, fmt.Sprintf("new session %s state is not valid: %s", returnedSession.PublicId, returnedSession.States[0].Status))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return returnedSession, privKey, nil
}

// LookupSession will look up a session in the repository and return the session
// with its states.  Returned States are ordered by start time descending.  If the
// session is not found, it will return nil, nil, nil. No options are currently
// supported.
func (r *Repository) LookupSession(ctx context.Context, sessionId string, _ ...Option) (*Session, *AuthzSummary, error) {
	const op = "session.(Repository).LookupSession"
	if sessionId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	session := AllocSession()
	session.PublicId = sessionId
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &session); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", sessionId)))
			}
			states, err := fetchStates(ctx, read, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			session.States = states

			var dynamicCreds []*DynamicCredential
			if err := read.SearchWhere(ctx, &dynamicCreds, "session_id = ?", []interface{}{sessionId}); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if len(dynamicCreds) > 0 {
				session.DynamicCredentials = dynamicCreds
			}

			var staticCreds []*StaticCredential
			if err := read.SearchWhere(ctx, &staticCreds, "session_id = ?", []interface{}{sessionId}); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if len(staticCreds) > 0 {
				session.StaticCredentials = staticCreds
			}

			connections, err := fetchConnections(ctx, read, sessionId, db.WithOrder("create_time desc"))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			session.Connections = connections
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil
		}
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	if len(session.CtTofuToken) > 0 {
		databaseWrapper, err := r.kms.GetWrapper(ctx, session.ProjectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := session.decrypt(ctx, databaseWrapper); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("cannot decrypt session value"))
		}
	} else {
		session.CtTofuToken = nil
	}

	authzSummary, err := r.sessionAuthzSummary(ctx, sessionId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to get authz summary"))
	}

	return &session, authzSummary, nil
}

// fetchAuthzProtectedSessionsByProject fetches sessions for the given projects.
// Note that the sessions are not fully populated, and only contain the
// necessary information to implement the boundary.AuthzProtectedEntity
// interface. Supports the WithTerminated option.
func (r *Repository) fetchAuthzProtectedSessionsByProject(
	ctx context.Context, projectIds []string, opt ...Option,
) (map[string][]boundary.AuthzProtectedEntity, error) {
	const op = "session.(Repository).fetchAuthzProtectedSessionsByProject"

	opts := getOpts(opt...)

	if len(projectIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no project ids given")
	}

	args := []interface{}{
		sql.Named("project_ids", "{"+strings.Join(projectIds, ",")+"}"),
	}

	var query string
	if opts.withTerminated {
		query = sessionPublicIdList
	} else {
		query = nonTerminatedSessionPublicIdList
	}

	rows, err := r.reader.Query(ctx, query, args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	sessionsMap := map[string][]boundary.AuthzProtectedEntity{}
	for rows.Next() {
		var ses Session
		if err := r.reader.ScanRows(ctx, rows, &ses); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		sessionsMap[ses.GetProjectId()] = append(sessionsMap[ses.GetProjectId()], ses)
	}

	return sessionsMap, nil
}

// ListSessions lists sessions.  Supports the WithLimit, WithProjectId, and WithSessionIds options.
func (r *Repository) ListSessions(ctx context.Context, opt ...Option) ([]*Session, error) {
	const op = "session.(Repository).ListSessions"
	opts := getOpts(opt...)
	var where []string
	var args []interface{}

	inClauseCnt := 0
	switch len(opts.withProjectIds) {
	case 0:
	case 1:
		inClauseCnt += 1
		where, args = append(where, fmt.Sprintf("project_id = @%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), opts.withProjectIds[0]))
	default:
		idsInClause := make([]string, 0, len(opts.withProjectIds))
		for _, id := range opts.withProjectIds {
			inClauseCnt += 1
			idsInClause, args = append(idsInClause, fmt.Sprintf("@%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), id))
		}
		where = append(where, fmt.Sprintf("project_id in (%s)", strings.Join(idsInClause, ",")))
	}

	if opts.withUserId != "" {
		inClauseCnt += 1
		where, args = append(where, fmt.Sprintf("user_id = @%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), opts.withUserId))
	}

	switch len(opts.withSessionIds) {
	case 0:
	case 1:
		inClauseCnt += 1
		where, args = append(where, fmt.Sprintf("s.public_id = @%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), opts.withSessionIds[0]))
	default:
		idsInClause := make([]string, 0, len(opts.withSessionIds))
		for _, id := range opts.withSessionIds {
			inClauseCnt += 1
			idsInClause, args = append(idsInClause, fmt.Sprintf("@%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), id))
		}
		where = append(where, fmt.Sprintf("s.public_id in (%s)", strings.Join(idsInClause, ",")))
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

	var withOrder string
	switch opts.withOrderByCreateTime {
	case db.AscendingOrderBy:
		withOrder = "order by create_time asc"
	case db.DescendingOrderBy:
		fallthrough
	default:
		withOrder = "order by create_time"
	}

	var whereClause string
	if len(where) > 0 {
		whereClause = " where " + strings.Join(where, " and ")
	}
	q := sessionList
	query := fmt.Sprintf(q, whereClause, withOrder, limit, withOrder)

	rows, err := r.reader.Query(ctx, query, args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var sessionsList []*sessionListView
	for rows.Next() {
		var s sessionListView
		if err := r.reader.ScanRows(ctx, rows, &s); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		sessionsList = append(sessionsList, &s)
	}
	sessions, err := r.convertToSessions(ctx, sessionsList, withListingConvert(true))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return sessions, nil
}

// DeleteSession will delete a session from the repository.
func (r *Repository) DeleteSession(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "session.(Repository).DeleteSession"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	session := AllocSession()
	session.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &session); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
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

// CancelSession sets a session's state to "canceling" in the repo.  It's called
// when the user cancels a session and the controller wants to update the
// session state to "canceling" for the given reason, so the workers can get the
// "canceling signal" during their next status heartbeat. CancelSession is
// idempotent.
func (r *Repository) CancelSession(ctx context.Context, sessionId string, sessionVersion uint32) (*Session, error) {
	const op = "session.(Repository).CancelSession"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if sessionVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session version")
	}
	s, ss, err := r.updateState(ctx, sessionId, sessionVersion, StatusCanceling)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	s.States = ss
	return s, nil
}

// TerminateCompletedSessions will terminate sessions in the repo based on:
//   - sessions that have exhausted their connection limit and all their connections are closed.
//   - sessions that are expired and all their connections are closed.
//   - sessions that are canceling and all their connections are closed
//
// This function should called on a periodic basis a Controllers via it's
// "ticker" pattern.
func (r *Repository) TerminateCompletedSessions(ctx context.Context) (int, error) {
	const op = "session.(Repository).TerminateCompletedSessions"
	var rowsAffected int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			rowsAffected, err = w.Exec(ctx, termSessionsUpdate, nil)
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

// terminateSessionIfPossible is called on connection close and will attempt to close the connection's
// session if the following conditions are met:
//   - sessions that have exhausted their connection limit and all their connections are closed.
//   - sessions that are expired and all their connections are closed.
//   - sessions that are canceling and all their connections are closed
func (r *Repository) terminateSessionIfPossible(ctx context.Context, sessionId string) (int, error) {
	const op = "session.(Repository).terminateSessionIfPossible"
	rowsAffected := 0

	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			rowsAffected, err = w.Exec(ctx, terminateSessionIfPossible,
				[]interface{}{sql.Named("public_id", sessionId)})
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

type AuthzSummary struct {
	ExpirationTime         *timestamp.Timestamp
	ConnectionLimit        int32
	CurrentConnectionCount uint32
}

func (r *Repository) sessionAuthzSummary(ctx context.Context, sessionId string) (*AuthzSummary, error) {
	const op = "session.(Repository).sessionAuthzSummary"
	rows, err := r.reader.Query(ctx, remainingConnectionsCte, []interface{}{sql.Named("session_id", sessionId)})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var info *AuthzSummary
	for rows.Next() {
		if info != nil {
			return nil, errors.New(ctx, errors.MultipleRecords, op, "query returned more than one row")
		}
		info = &AuthzSummary{}
		if err := r.reader.ScanRows(ctx, rows, info); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
	}
	return info, nil
}

// ActivateSession will activate the session and is called by a worker after
// authenticating the session. The session must be in a "pending" state to be
// activated. States are ordered by start time descending. Returns an
// InvalidSessionState error code if a connection cannot be made because the session
// was canceled or terminated.
func (r *Repository) ActivateSession(ctx context.Context, sessionId string, sessionVersion uint32, tofuToken []byte) (*Session, []*State, error) {
	const op = "session.(Repository).ActivateSession"
	if sessionId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if sessionVersion == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if len(tofuToken) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing tofu token")
	}

	updatedSession := AllocSession()
	updatedSession.PublicId = sessionId
	var returnedStates []*State
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rowsAffected, err := w.Exec(ctx, activateStateCte, []interface{}{
				sql.Named("session_id", sessionId),
				sql.Named("version", sessionVersion),
			})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to activate session %s", sessionId)))
			}
			if rowsAffected == 0 {
				return errors.New(ctx, errors.InvalidSessionState, op, "session is not in a pending state")
			}
			foundSession := AllocSession()
			foundSession.PublicId = sessionId
			if err := reader.LookupById(ctx, &foundSession); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", sessionId)))
			}
			databaseWrapper, err := r.kms.GetWrapper(ctx, foundSession.ProjectId, kms.KeyPurposeDatabase)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
			}
			if len(foundSession.TofuToken) > 0 && subtle.ConstantTimeCompare(foundSession.TofuToken, tofuToken) != 1 {
				return errors.New(ctx, errors.TokenMismatch, op, "tofu token mismatch")
			}

			updatedSession.TofuToken = tofuToken
			if err := updatedSession.encrypt(ctx, databaseWrapper); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			rowsUpdated, err := w.Update(ctx, &updatedSession, []string{"CtTofuToken"}, nil)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}

			returnedStates, err = fetchStates(ctx, reader, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return &updatedSession, returnedStates, nil
}

// updateState will update the session's state using the session id and its
// version. updateState is idempotent. States are ordered by start time
// descending. No options are currently supported.
func (r *Repository) updateState(ctx context.Context, sessionId string, sessionVersion uint32, s Status, _ ...Option) (*Session, []*State, error) {
	const op = "session.(Repository).updateState"
	if sessionId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if sessionVersion == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if s == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing session status")
	}
	if s == StatusActive {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "you must call ActivateSession to update a session's state to active")
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
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated session and %d rows updated", rowsUpdated))
			}
			if len(updatedSession.CtTofuToken) > 0 {
				databaseWrapper, err := r.kms.GetWrapper(ctx, updatedSession.ProjectId, kms.KeyPurposeDatabase)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
				}
				if err := updatedSession.decrypt(ctx, databaseWrapper); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("cannot decrypt session value"))
				}
			} else {
				updatedSession.CtTofuToken = nil
			}

			rowsAffected, err = w.Exec(ctx, updateSessionState, []interface{}{
				sql.Named("session_id", sessionId),
				sql.Named("status", s.String()),
			})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to update session %s state to %s", sessionId, s.String())))
			}
			if rowsAffected != 0 && rowsAffected != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated session %s to state %s and %d rows inserted (should be 0 or 1)", sessionId, s.String(), rowsAffected))
			}
			returnedStates, err = fetchStates(ctx, reader, sessionId, db.WithOrder("start_time desc"))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if len(returnedStates) < 1 && returnedStates[0].Status != s {
				return errors.New(ctx, errors.InvalidSessionState, op, fmt.Sprintf("failed to update %s to a state of %s", sessionId, s.String()))
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new state"))
	}
	return &updatedSession, returnedStates, nil
}

// checkIfNoLongerActive checks the given sessions to see if they are in a
// non-active state, i.e. "canceling" or "terminated"
// It returns a []StateReport for each session that is not active, with its current status.
func (r *Repository) checkIfNoLongerActive(ctx context.Context, reportedSessions []string) ([]StateReport, error) {
	const op = "session.(Repository).checkIfNotActive"

	notActive := make([]StateReport, 0, len(reportedSessions))
	args := make([]interface{}, 0, len(reportedSessions))
	var inClause string

	if len(reportedSessions) <= 0 {
		return notActive, nil
	}

	inClause = `and session_id in (%s)`
	params := make([]string, len(reportedSessions))
	for i, sessId := range reportedSessions {
		params[i] = fmt.Sprintf("@%d", i)
		args = append(args, sql.Named(fmt.Sprintf("%d", i), sessId))
	}
	inClause = fmt.Sprintf(inClause, strings.Join(params, ","))

	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rows, err := r.reader.Query(ctx, fmt.Sprintf(checkIfNotActive, inClause), args)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			defer rows.Close()

			for rows.Next() {
				var sessionId string
				var status Status
				if err := rows.Scan(&sessionId, &status); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
				}
				notActive = append(notActive, StateReport{
					SessionId: sessionId,
					Status:    status,
				})
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error checking if sessions are no longer active"))
	}
	return notActive, nil
}

func (r *Repository) deleteSessionsTerminatedBefore(ctx context.Context, threshold time.Duration) (int, error) {
	const op = "session.(Repository).deleteTerminated"

	args := []any{
		sql.Named("threshold_seconds", threshold.Seconds()),
	}

	c, err := r.writer.Exec(ctx, deleteTerminated, args)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("error deleting terminated sessions"))
	}
	return c, nil
}

func fetchStates(ctx context.Context, r db.Reader, sessionId string, opt ...db.Option) ([]*State, error) {
	const op = "session.fetchStates"
	var states []*State
	if err := r.SearchWhere(ctx, &states, "session_id = ?", []interface{}{sessionId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(states) == 0 {
		return nil, nil
	}
	return states, nil
}

func fetchConnections(ctx context.Context, r db.Reader, sessionId string, opt ...db.Option) ([]*Connection, error) {
	const op = "session.fetchConnections"
	var connections []*Connection
	if err := r.SearchWhere(ctx, &connections, "session_id = ?", []interface{}{sessionId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(connections) == 0 {
		return nil, nil
	}
	return connections, nil
}
