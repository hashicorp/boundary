package usersessions

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/usersessions/store"
)

// A Repository stores and retrieves the persistent types in the usersessions
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it.
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (*Repository, error) {
	switch {
	case r == nil:
		return nil, fmt.Errorf("db.Reader: user session: %w", db.ErrNilParameter)
	case w == nil:
		return nil, fmt.Errorf("db.Writer: user session: %w", db.ErrNilParameter)
	case wrapper == nil:
		return nil, fmt.Errorf("wrapping.Wrapper: user session: %w", db.ErrNilParameter)
	}

	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// CreateSession inserts s into the repository and returns a new Session containing the session's PublicId
// and token. s is not changed. s must contain a valid ScopeID, UserID, and AuthMethodID.  The scopes for
// the user, auth method, and this session must all be the same.  s must not contain a PublicId nor a Token.
// The PublicId and token are generated and assigned by this method. opt is ignored.
//
// Both s.CreateTime and s.UpdateTime are ignored.
func (r *Repository) CreateSession(ctx context.Context, s *Session, opt ...Option) (*Session, error) {
	if s == nil {
		return nil, fmt.Errorf("create: user session: %w", db.ErrNilParameter)
	}
	if s.Session == nil {
		return nil, fmt.Errorf("create: user session: embedded Session: %w", db.ErrNilParameter)
	}
	if s.IamScopeId == "" {
		return nil, fmt.Errorf("create: user session: no scope id: %w", db.ErrInvalidParameter)
	}
	if s.IamUserId == "" {
		return nil, fmt.Errorf("create: user session: no user id: %w", db.ErrInvalidParameter)
	}
	if s.AuthMethodId == "" {
		return nil, fmt.Errorf("create: user session: no auth method id: %w", db.ErrInvalidParameter)
	}
	if s.PublicId != "" {
		return nil, fmt.Errorf("create: user session: public id not empty: %w", db.ErrInvalidParameter)
	}
	if s.Token != "" {
		return nil, fmt.Errorf("create: user session: token not empty: %w", db.ErrInvalidParameter)
	}
	s = s.clone()

	id, err := newSessionId()
	if err != nil {
		return nil, fmt.Errorf("create: user session: %w", err)
	}
	s.PublicId = id

	token, err := newSessionToken()
	if err != nil {
		return nil, fmt.Errorf("create: user session: %w", err)
	}
	s.Token = token

	metadata := newSessionMetadata(s, oplog.OpType_OP_TYPE_CREATE)

	var newSession *Session
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			newSession = s.clone()
			return w.Create(
				ctx,
				newSession,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)

	if err != nil {
		return nil, fmt.Errorf("create: user session: in scope: %s: %w", s.IamScopeId, err)
	}
	return newSession, nil
}

// LookupSession returns the Session for id. Returns nil, nil if no Session is found for id.
// Token is not returned in the returned Session. All options are ignored.
func (r *Repository) LookupSession(ctx context.Context, id string, opt ...Option) (*Session, error) {
	if id == "" {
		return nil, fmt.Errorf("lookup: user session: missing public id: %w", db.ErrInvalidParameter)
	}
	s := allocSession()
	s.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, s); err != nil {
		if err == db.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup: user session: %s: %w", id, err)
	}
	s.Token = ""
	return s, nil
}

// UpdateLastAccessed updates the last accessed field and returns a Session with the previous value for Last Accessed
// populated. Returns nil, nil if no Session is found for the token.  All options are ignored.
func (r *Repository) UpdateLastUsed(ctx context.Context, token string, opt ...Option) (*Session, error) {
	if token == "" {
		return nil, fmt.Errorf("lookup: user session: missing token: %w", db.ErrInvalidParameter)
	}
	s := allocSession()
	if err := r.reader.LookupWhere(ctx, &s, "token = ?", token); err != nil {
		if err == db.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup by token: user session: %w", err)
	}
	s.Token = ""
	metadata := newSessionMetadata(s, oplog.OpType_OP_TYPE_UPDATE)

	// TODO: Issue the lookup in the same transaction as the Update.
	var rowsUpdated int
	var sess *Session
	_, err := r.writer.DoTx(
		ctx,
		0,
		db.ExpBackoff{},
		func(w db.Writer) error {
			sess = s.clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				sess,
				nil,
				[]string{"LastAccessTime"},
				db.WithOplog(r.wrapper, metadata),
			)
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return nil, fmt.Errorf("update: user session: %s: %w", s.PublicId, err)
	}
	return s, nil
}

// TODO(ICU-344): Add ListSessions

// DeleteSession deletes id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteSession(ctx context.Context, id string, opt ...Option) (int, error) {
	if id == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: user session: missing public id: %w", db.ErrInvalidParameter)
	}

	s := allocSession()
	s.PublicId = id

	metadata := newSessionMetadata(s, oplog.OpType_OP_TYPE_DELETE)

	var rowsDeleted int
	var deleteSession *Session
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			deleteSession = s.clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteSession,
				db.WithOplog(r.wrapper, metadata),
			)
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: user session: %s: %w", s.PublicId, err)
	}

	return rowsDeleted, nil
}

func allocSession() *Session {
	fresh := &Session{
		Session: &store.Session{},
	}
	return fresh
}

func newSessionMetadata(s *Session, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{s.GetPublicId()},
		"resource-type":      []string{"user session"},
		"op-type":            []string{op.String()},
	}
	if s.IamScopeId != "" {
		metadata["scope-id"] = []string{s.IamScopeId}
	}
	return metadata
}
