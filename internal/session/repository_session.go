// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/util"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateSession inserts into the repository and returns the new Session with
// its State of "Pending".  The following fields must be empty when creating a
// session: WorkerId, and PublicId.  No options are
// currently supported.
func (r *Repository) CreateSession(ctx context.Context, sessionWrapper wrapping.Wrapper, newSession *Session, workerAddresses []string, _ ...Option) (*Session, error) {
	const op = "session.(Repository).CreateSession"
	if newSession == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session")
	}
	if newSession.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id is not empty")
	}
	if len(newSession.Certificate) != 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "certificate is not empty")
	}
	if newSession.TargetId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if newSession.UserId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	if newSession.AuthTokenId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token id")
	}
	if newSession.ProjectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if newSession.HostId == "" && newSession.HostSetId == "" && newSession.Endpoint == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing host source and endpoint")
	}
	if newSession.CtTofuToken != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "ct is not empty")
	}
	if newSession.TofuToken != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "tofu token is not empty")
	}
	if newSession.ExpirationTime == nil || newSession.ExpirationTime.Timestamp.AsTime().IsZero() {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing expiration time")
	}
	if len(workerAddresses) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing addresses")
	}

	id, err := newId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	privKey, certBytes, err := newCert(ctx, id, workerAddresses, newSession.ExpirationTime.Timestamp.AsTime(), r.randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	newSession.Certificate = certBytes
	newSession.CertificatePrivateKey = privKey
	newSession.PublicId = id
	if err := newSession.encrypt(ctx, sessionWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to encrypt session"))
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

			if newSession.HostSetId != "" && newSession.HostId != "" {
				hs, err := NewSessionHostSetHost(ctx, newSession.PublicId, newSession.HostSetId, newSession.HostId)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if err = w.Create(ctx, hs); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				returnedSession.HostSetId = hs.HostSetId
				returnedSession.HostId = hs.HostId
			} else if newSession.Endpoint != "" {
				ta, err := NewSessionTargetAddress(ctx, newSession.PublicId, newSession.TargetId)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if err = w.Create(ctx, ta); err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}

			if newSession.ProtocolWorkerId != "" {
				swp, err := NewSessionWorkerProtocol(ctx, newSession.PublicId, newSession.ProtocolWorkerId)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if err = w.Create(ctx, swp); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				returnedSession.ProtocolWorkerId = swp.WorkerId
			}

			for _, cred := range newSession.DynamicCredentials {
				cred.SessionId = newSession.PublicId
			}

			var staticCreds []any
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
				if err := read.SearchWhere(ctx, &c, "session_id = ?", []any{newSession.PublicId}); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				returnedSession.StaticCredentials = c
			}

			// TODO: after upgrading to gorm v2 this batch insert can be replaced, since gorm v2 supports batch inserts
			q, batchInsertArgs, err := batchInsertSessionCredentialDynamic(newSession.DynamicCredentials)
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
		return nil, errors.Wrap(ctx, err, op)
	}
	return returnedSession, nil
}

// LookupSession will look up a session in the repository and return the session
// with its states.  Returned States are ordered by start time descending.  If the
// session is not found, it will return nil, nil, nil. If the session has no user
// or project associated with it, decryption of fields will not be performed.
// Supported Options:
//   - WithIgnoreDecryptionFailures
func (r *Repository) LookupSession(ctx context.Context, sessionId string, opt ...Option) (*Session, *AuthzSummary, error) {
	const op = "session.(Repository).LookupSession"
	if sessionId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	opts := getOpts(opt...)
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
			if err := read.SearchWhere(ctx, &dynamicCreds, "session_id = ?", []any{sessionId}); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if len(dynamicCreds) > 0 {
				session.DynamicCredentials = dynamicCreds
			}

			var staticCreds []*StaticCredential
			if err := read.SearchWhere(ctx, &staticCreds, "session_id = ?", []any{sessionId}); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if len(staticCreds) > 0 {
				session.StaticCredentials = staticCreds
			}

			sessionHostSetHost := AllocSessionHostSetHost()
			if err := read.LookupWhere(ctx, sessionHostSetHost, "session_id = ?", []any{sessionId}); err != nil && !errors.IsNotFoundError(err) {
				return errors.Wrap(ctx, err, op)
			}
			session.HostSetId = sessionHostSetHost.HostSetId
			session.HostId = sessionHostSetHost.HostId

			sessionWorkerProtocol := AllocSessionWorkerProtocol()
			if err := read.LookupWhere(ctx, sessionWorkerProtocol, "session_id = ?", []any{sessionId}); err != nil && !errors.IsNotFoundError(err) {
				return errors.Wrap(ctx, err, op)
			}
			session.ProtocolWorkerId = sessionWorkerProtocol.WorkerId

			connections, err := fetchConnections(ctx, read, sessionId, db.WithOrder("create_time desc"))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			session.Connections = connections
			if session.ProjectId == "" || session.UserId == "" {
				// Skip decryption if Project ID or UserId is missing,
				// since it will just lead to errors, and the session
				// is already canceled if either of those are empty.
				return nil
			}
			if err := decryptAndMaybeUpdateSession(ctx, r.kms, &session, w); err != nil && !opts.withIgnoreDecryptionFailures {
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

	authzSummary, err := r.sessionAuthzSummary(ctx, sessionId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to get authz summary"))
	}

	return &session, authzSummary, nil
}

// ListSessions lists sessions. Sessions returned will be limited by the list
// permissions of the repository. Supports the WithTerminated, WithLimit,
// WithOrderByCreateTime options.
func (r *Repository) ListSessions(ctx context.Context, opt ...Option) ([]*Session, error) {
	const op = "session.(Repository).ListSessions"
	opts := getOpts(opt...)

	where, args := r.listPermissionWhereClauses()
	if len(where) == 0 {
		return nil, nil
	}

	var whereClause string
	if len(where) > 0 {
		whereClause = " where (" + strings.Join(where, " or ") + ")"
		if !opts.withTerminated {
			whereClause += "and termination_reason is null"
		}
	} else {
		if !opts.withTerminated {
			whereClause = "where termination_reason is null"
		}
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
	sessions, err := r.convertToSessions(ctx, sessionsList)
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
// Supported Options:
//   - WithIgnoreDecryptionFailures
func (r *Repository) CancelSession(ctx context.Context, sessionId string, sessionVersion uint32, opt ...Option) (*Session, error) {
	const op = "session.(Repository).CancelSession"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if sessionVersion == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session version")
	}
	s, ss, err := r.updateState(ctx, sessionId, sessionVersion, StatusCanceling, opt...)
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
				[]any{sql.Named("public_id", sessionId)})
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
	EgressWorkerFilter     string
	IngressWorkerFilter    string
}

func (r *Repository) sessionAuthzSummary(ctx context.Context, sessionId string) (*AuthzSummary, error) {
	const op = "session.(Repository).sessionAuthzSummary"
	rows, err := r.reader.Query(ctx, remainingConnectionsCte, []any{sql.Named("session_id", sessionId)})
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

// Lookup an activated session. Must run in a transaction.
func (r *Repository) lookupActivatedSessionTx(ctx context.Context, reader db.Reader, writer db.Writer, sessionId string,
	tofuToken []byte, activatedSession *Session,
) error {
	const op = "session.(Repository).lookupActivatedSessionTx"
	var txErr error
	if txErr = reader.LookupById(ctx, activatedSession); txErr != nil {
		return errors.Wrap(ctx, txErr, op, errors.WithMsg(fmt.Sprintf("failed for %s", sessionId)))
	}
	if txErr = decryptAndMaybeUpdateSession(ctx, r.kms, activatedSession, writer); txErr != nil {
		return errors.Wrap(ctx, txErr, op)
	}
	if len(activatedSession.TofuToken) > 0 && subtle.ConstantTimeCompare(activatedSession.TofuToken, tofuToken) != 1 {
		return errors.New(ctx, errors.TokenMismatch, op, "tofu token mismatch")
	}

	return nil
}

// Return states for an activated session. Must run in a transaction.
func (r *Repository) fetchActivatedSessionStatesTx(ctx context.Context, reader db.Reader, sessionId string) ([]*State, error) {
	const op = "session.(Repository).fetchActivatedSessionStatesTx"
	var txErr error

	var returnedStates []*State
	returnedStates, txErr = fetchStates(ctx, reader, sessionId, db.WithOrder("start_time desc"))
	if txErr != nil {
		return nil, errors.Wrap(ctx, txErr, op)
	}
	return returnedStates, nil
}

// getActivatedSession is called if there was a duplicate attempt to activate a session
// It validates the tofu token matches and returns the session
func (r *Repository) getActivatedSession(ctx context.Context, sessionId string, tofuToken []byte) (*Session, []*State, error) {
	const op = "session.(Repository).getActivatedSession"

	activatedSession := AllocSession()
	activatedSession.PublicId = sessionId
	var returnedStates []*State
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			err := r.lookupActivatedSessionTx(ctx, reader, w, sessionId, tofuToken, &activatedSession)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			returnedStates, err = r.fetchActivatedSessionStatesTx(ctx, reader, sessionId)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return &activatedSession, returnedStates, nil
}

// ActivateSession will activate the session and is called by a worker after
// authenticating the session. The session must be in a "pending" state to be
// activated. States are ordered by start time descending. Returns an
// InvalidSessionState error code if a connection cannot be made because the session
// was canceled or terminated.
// If ActivateSession receives duplicate requests for the same session, it will return the
// already active session if the tofu token is correct
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
			rowsAffected, err := w.Exec(ctx, activateStateCte, []any{
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
			err = r.lookupActivatedSessionTx(ctx, reader, w, sessionId, tofuToken, &foundSession)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}

			updatedSession.TofuToken = tofuToken
			sessionWrapper, err := r.kms.GetWrapper(ctx, foundSession.ProjectId, kms.KeyPurposeSessions)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get session wrapper"))
			}
			if err := updatedSession.encrypt(ctx, sessionWrapper); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			rowsUpdated, err := w.Update(ctx, &updatedSession, []string{"CtTofuToken", "KeyId"}, nil)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if err == nil && rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}

			returnedStates, err = r.fetchActivatedSessionStatesTx(ctx, reader, sessionId)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		// If this was a duplicate activation attempt, return existing session if the tofu token matches
		if errors.IsUniqueError(err) {
			event.WriteSysEvent(ctx, op, fmt.Sprintf("ignoring duplicate session activation attempt for session %v", sessionId))
			return r.getActivatedSession(ctx, sessionId, tofuToken)
		}
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return &updatedSession, returnedStates, nil
}

// updateState will update the session's state using the session id and its
// version. updateState is idempotent. States are ordered by start time
// descending. No options are currently supported.
// Supported Options:
//   - WithIgnoreDecryptionFailures
func (r *Repository) updateState(ctx context.Context, sessionId string, sessionVersion uint32, s Status, opt ...Option) (*Session, []*State, error) {
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
	opts := getOpts(opt...)

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
			if err := decryptAndMaybeUpdateSession(ctx, r.kms, &updatedSession, w); err != nil && !opts.withIgnoreDecryptionFailures {
				return errors.Wrap(ctx, err, op)
			}

			rowsAffected, err = w.Exec(ctx, updateSessionState, []any{
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
			hostSetHost, err := fetchHostSetHost(ctx, reader, sessionId)
			if err != nil && !errors.IsNotFoundError(err) {
				return errors.Wrap(ctx, err, op)
			}
			updatedSession.HostId = hostSetHost.HostId
			updatedSession.HostSetId = hostSetHost.HostSetId
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new state"))
	}
	return &updatedSession, returnedStates, nil
}

// CheckIfNotActive checks the given sessions to see if they are in a
// non-active state, i.e. "canceling" or "terminated" It returns a *StateReport
// object for each session that is not active, with its current status.
func (r *Repository) CheckIfNotActive(ctx context.Context, reportedSessions []string) ([]*StateReport, error) {
	const op = "session.(Repository).listSessionIdAndState"

	notActive := make([]*StateReport, 0, len(reportedSessions))
	if len(reportedSessions) <= 0 {
		return notActive, nil
	}

	unrecognizedSessions := make(map[string]struct{})
	for _, sessId := range reportedSessions {
		unrecognizedSessions[sessId] = struct{}{}
	}

	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var states []*State
			err := r.reader.SearchWhere(ctx, &states, "end_time is null and session_id in (?)", []any{reportedSessions})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}

			for _, s := range states {
				delete(unrecognizedSessions, s.SessionId)
				switch s.Status {
				case StatusPending, StatusActive:
					continue
				case StatusCanceling, StatusTerminated:
				default:
					return errors.New(ctx, errors.Internal, op, fmt.Sprintf("unknown session state %q", s.Status))
				}

				notActive = append(notActive, &StateReport{
					SessionId: s.SessionId,
					Status:    s.Status,
				})
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error checking if sessions are no longer active"))
	}

	for s := range unrecognizedSessions {
		notActive = append(notActive, &StateReport{
			SessionId:    s,
			Unrecognized: true,
		})
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
	if err := r.SearchWhere(ctx, &states, "session_id = ?", []any{sessionId}, opt...); err != nil {
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
	if err := r.SearchWhere(ctx, &connections, "session_id = ?", []any{sessionId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(connections) == 0 {
		return nil, nil
	}
	return connections, nil
}

func fetchHostSetHost(ctx context.Context, r db.Reader, sessionId string, opt ...db.Option) (*SessionHostSetHost, error) {
	const op = "session.fetchHostSetHost"
	var hostSetHost *SessionHostSetHost
	if err := r.SearchWhere(ctx, &hostSetHost, "session_id = ?", []any{sessionId}, opt...); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return hostSetHost, nil
}

// decryptAndMaybeUpdateSession switches between the database key and session key based on whether
// the session uses a legacy private key or not. It also updates the encrypted session
// in the database (if necessary). Eventually we should be able to remove this function
// and use the session key unconditionally.
func decryptAndMaybeUpdateSession(ctx context.Context, kmsRepo kms.GetWrapperer, session *Session, writer db.Writer) error {
	const op = "session.decryptAndMaybeUpdateSession"
	if util.IsNil(kmsRepo) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms repo")
	}
	if session == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session")
	}
	if util.IsNil(writer) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	}
	if session.ProjectId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session project ID")
	}
	if session.KeyId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session key ID")
	}
	if session.UserId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session user ID")
	}
	if session.PublicId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session ID")
	}
	sessionWrapper, err := kmsRepo.GetWrapper(ctx, session.ProjectId, kms.KeyPurposeSessions, kms.WithKeyId(session.KeyId))
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get session wrapper"))
	}
	if len(session.CtCertificatePrivateKey) > 0 {
		// New-style session with private key stored in DB, just decrypt.
		if err := session.decrypt(ctx, sessionWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to decrypt session value"))
		}
		return nil
	}
	// No certificate private key present, this is a legacy session with a
	// private key derived from the key. Derive it again and store it back
	// in the DB.
	_, session.CertificatePrivateKey, err = DeriveED25519Key(ctx, sessionWrapper, session.UserId, session.PublicId)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("Error deriving session key"))
	}
	updatedFields := []string{"CtCertificatePrivateKey", "KeyId"}
	if len(session.CtTofuToken) > 0 {
		// If the TOFU token was set on this session, we can decrypt it using
		// the database key.
		databaseWrapper, err := kmsRepo.GetWrapper(ctx, session.ProjectId, kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := session.decrypt(ctx, databaseWrapper); err != nil {
			// Note; we can hit this error if the database key that
			// was used to encrypt the TOFU token is no longer available
			// in the wrapper. Try to return a useful error to the user.
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to decrypt session TOFU token. You may need to recreate your session."))
		}
		updatedFields = append(updatedFields, "CtTofuToken")
	}
	// Rewrap with the session wrapper. Next time we look up this session
	// all values will be encrypted using the session key.
	if err := session.encrypt(ctx, sessionWrapper); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to encrypt session value"))
	}
	if _, err := writer.Update(ctx, session, updatedFields, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update session value"))
	}
	return nil
}
