package authtoken

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping"

	"github.com/hashicorp/watchtower/internal/authtoken/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// A Repository stores and retrieves the persistent types in the authtoken
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
		return nil, fmt.Errorf("db.Reader: auth token: %w", db.ErrNilParameter)
	case w == nil:
		return nil, fmt.Errorf("db.Writer: auth token: %w", db.ErrNilParameter)
	case wrapper == nil:
		return nil, fmt.Errorf("wrapping.Wrapper: auth token: %w", db.ErrNilParameter)
	}

	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// CreateAuthToken inserts s into the repository and returns a new AuthToken containing the auth token's PublicId
// and token. s is not changed. s must contain a valid ScopeID, UserID, and AuthMethodID.  The scopes for
// the user, auth method, and this auth token must all be the same.  s must not contain a PublicId nor a Token.
// The PublicId and token are generated and assigned by this method. opt is ignored.
//
// Both s.CreateTime and s.UpdateTime are ignored.
func (r *Repository) CreateAuthToken(ctx context.Context, at *AuthToken, opt ...Option) (*AuthToken, error) {
	if at == nil {
		return nil, fmt.Errorf("create: auth token: %w", db.ErrNilParameter)
	}
	if at.AuthToken == nil {
		return nil, fmt.Errorf("create: auth token: embedded AuthToken: %w", db.ErrNilParameter)
	}
	if at.ScopeId == "" {
		return nil, fmt.Errorf("create: auth token: no scope id: %w", db.ErrInvalidParameter)
	}
	if at.IamUserId == "" {
		return nil, fmt.Errorf("create: auth token: no user id: %w", db.ErrInvalidParameter)
	}
	if at.AuthMethodId == "" {
		return nil, fmt.Errorf("create: auth token: no auth method id: %w", db.ErrInvalidParameter)
	}
	if at.PublicId != "" {
		return nil, fmt.Errorf("create: auth token: public id not empty: %w", db.ErrInvalidParameter)
	}
	if at.Token != "" {
		return nil, fmt.Errorf("create: auth token: token not empty: %w", db.ErrInvalidParameter)
	}
	at = at.clone()

	id, err := newAuthTokenId()
	if err != nil {
		return nil, fmt.Errorf("create: auth token: %w", err)
	}
	at.PublicId = id

	token, err := newAuthToken()
	if err != nil {
		return nil, fmt.Errorf("create: auth token: %w", err)
	}
	at.Token = token

	metadata := newAuthTokenMetadata(at, oplog.OpType_OP_TYPE_CREATE)

	var newAuthToken *AuthToken
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newAuthToken = at.clone()
			return w.Create(
				ctx,
				newAuthToken,
				db.WithOplog(r.wrapper, metadata),
			)
		},
	)

	if err != nil {
		return nil, fmt.Errorf("create: auth token: %v: %w", at, err)
	}
	return newAuthToken, nil
}

// LookupAuthToken returns the AuthToken for id. Returns nil, nil if no AuthToken is found for id.
// For security reasons, the actual token is not included in the returned AuthToken.
func (r *Repository) LookupAuthToken(ctx context.Context, id string, opt ...Option) (*AuthToken, error) {
	if id == "" {
		return nil, fmt.Errorf("lookup: auth token: missing public id: %w", db.ErrInvalidParameter)
	}
	at := allocAuthToken()
	at.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, at); err != nil {
		if err == db.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup: auth token: %s: %w", id, err)
	}
	at.Token = ""
	return at, nil
}

// UpdateLastAccessed updates the last accessed field and returns a AuthToken with the previous value for Last Accessed
// populated. Returns nil, nil if no AuthToken is found for the token.  All options are ignored.
func (r *Repository) UpdateLastUsed(ctx context.Context, token string, opt ...Option) (*AuthToken, error) {
	if token == "" {
		return nil, fmt.Errorf("lookup: auth token: missing token: %w", db.ErrInvalidParameter)
	}
	authToken := allocAuthToken()

	var rowsUpdated int
	var at *AuthToken
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupWhere(ctx, &authToken, "token = ?", token); err != nil {
				return fmt.Errorf("lookup by token: auth token: %w", err)
			}
			authToken.Token = ""
			metadata := newAuthTokenMetadata(authToken, oplog.OpType_OP_TYPE_UPDATE)

			at = authToken.clone()
			var err error
			rowsUpdated, err = w.Update(
				ctx,
				at,
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
		return nil, fmt.Errorf("update: auth token: %s: %w", authToken.PublicId, err)
	}
	return authToken, nil
}

// TODO(ICU-344): Add ListAuthTokens

// DeleteAuthToken deletes id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAuthToken(ctx context.Context, id string, opt ...Option) (int, error) {
	if id == "" {
		return db.NoRowsAffected, fmt.Errorf("delete: auth token: missing public id: %w", db.ErrInvalidParameter)
	}

	at, err := r.LookupAuthToken(ctx, id)
	if err != nil {
		return 0, fmt.Errorf("delete: auth token: lookup %w", err)
	}

	metadata := newAuthTokenMetadata(at, oplog.OpType_OP_TYPE_DELETE)

	var rowsDeleted int
	var deleteAT *AuthToken
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteAT = at.clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteAT,
				db.WithOplog(r.wrapper, metadata),
			)
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete: auth token: %s: %w", at.PublicId, err)
	}

	return rowsDeleted, nil
}

func allocAuthToken() *AuthToken {
	fresh := &AuthToken{
		AuthToken: &store.AuthToken{},
	}
	return fresh
}

func newAuthTokenMetadata(a *AuthToken, op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"scope-id":           []string{a.ScopeId},
		"resource-public-id": []string{a.GetPublicId()},
		"resource-type":      []string{"auth token"},
		"op-type":            []string{op.String()},
	}
	return metadata
}
