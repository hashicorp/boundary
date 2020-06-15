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
		return nil, fmt.Errorf("db.Reader: %w", db.ErrNilParameter)
	case w == nil:
		return nil, fmt.Errorf("db.Writer: %w", db.ErrNilParameter)
	case wrapper == nil:
		return nil, fmt.Errorf("wrapping.Wrapper: %w", db.ErrNilParameter)
	}

	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// CreateSession inserts s into the repository and returns a new
// Session containing the session's PublicId. c is not changed. c must
// contain a valid ScopeID. c must not contain a PublicId. The PublicId is
// generated and assigned by the this method. opt is ignored.
//
// Both c.Name and c.Description are optional. If c.Name is set, it must be
// unique within c.ScopeID.
//
// Both c.CreateTime and c.UpdateTime are ignored.
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

// LookupSession returns the Session for id. Returns nil, nil if no
// Session is found for id.
func (r *Repository) LookupSession(ctx context.Context, id string, opt ...Option) (*Session, error) {
	if id == "" {
		return nil, fmt.Errorf("lookup: user session: missing public id: %w", db.ErrInvalidParameter)
	}
	c := allocSession()
	c.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, c); err != nil {
		if err == db.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup: user session: %s: %w", id, err)
	}
	return c, nil
}

// DeleteSession deletes id from the repository returning a count of the
// number of records deleted.
func (r *Repository) DeleteSession(ctx context.Context, id string, opt ...Option) (int, error) {
	if id == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: user session: missing public id: %w", db.ErrInvalidParameter)
	}

	c := allocSession()
	c.PublicId = id

	metadata := newSessionMetadata(c, oplog.OpType_OP_TYPE_DELETE)

	var rowsDeleted int
	var deleteSession *Session
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(w db.Writer) error {
			deleteSession = c.clone()
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
		return db.NoRowsAffected, fmt.Errorf("delete: user session: %s: %w", c.PublicId, err)
	}

	return rowsDeleted, nil
}

func allocSession() *Session {
	fresh := &Session{
		Session: &store.Session{},
	}
	return fresh
}

func newSessionMetadata(c *Session, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.GetPublicId()},
		"resource-type":      []string{"user sessions"},
		"op-type":            []string{op.String()},
	}
	if c.IamScopeId != "" {
		metadata["scope-id"] = []string{c.IamScopeId}
	}
	return metadata
}
