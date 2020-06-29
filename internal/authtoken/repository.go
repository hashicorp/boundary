package authtoken

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db/timestamp"
	"github.com/hashicorp/watchtower/internal/iam"
	iamStore "github.com/hashicorp/watchtower/internal/iam/store"

	"github.com/hashicorp/watchtower/internal/authtoken/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// TODO: Make these fields configurable.
var (
	lastAccessedUpdateDuration = 10 * time.Minute
	maxStaleness               = 24 * time.Hour
	maxTokenDuration           = 7 * 24 * time.Hour
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
func (r *Repository) CreateAuthToken(ctx context.Context, withIamUserId, withAuthMethodId string, opt ...Option) (*AuthToken, error) {
	if withIamUserId == "" {
		return nil, fmt.Errorf("create: auth token: no user id: %w", db.ErrInvalidParameter)
	}
	if withAuthMethodId == "" {
		return nil, fmt.Errorf("create: auth token: no auth method id: %w", db.ErrInvalidParameter)
	}

	user, err := r.getUserWithIdAndAuthMethod(withIamUserId, withAuthMethodId)
	if err != nil {
		return nil, fmt.Errorf("create: auth token: user lookup: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("create: auth token: user lookup: user not found with auth method")
	}

	at := allocAuthToken()
	at.IamUserId = user.GetPublicId()
	at.ScopeId = user.GetScopeId()
	at.AuthMethodId = withAuthMethodId

	id, err := newAuthTokenId()
	if err != nil {
		return nil, fmt.Errorf("create: auth token id: %w", err)
	}
	at.PublicId = id

	token, err := newAuthToken()
	if err != nil {
		return nil, fmt.Errorf("create: auth token value: %w", err)
	}
	at.Token = token

	// TODO: Allow the caller to specify something different than the default duration.
	expiration, err := ptypes.TimestampProto(time.Now().Add(maxTokenDuration))
	if err != nil {
		return nil, err
	}
	at.ExpirationTime = &timestamp.Timestamp{Timestamp: expiration}

	metadata := newAuthTokenMetadata(at, oplog.OpType_OP_TYPE_CREATE)

	var newAuthToken *AuthToken
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {

			newAuthToken = at.clone()
			if err := newAuthToken.EncryptData(ctx, r.wrapper); err != nil {
				return err
			}
			if err := w.Create(ctx, newAuthToken, db.WithOplog(r.wrapper, metadata)); err != nil {
				return err
			}
			newAuthToken.CtToken = nil

			return nil
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
	at.CtToken = nil
	return at, nil
}

// ValidateToken returns a token from storage if the auth token with the provided id and token exists.  The
// approximate last accessed time may be updated depending on how long it has been since the last time the token
// was validated.  A token being returned does not mean that it hasn't expired.
// For security reasons, the actual token value is not included in the returned AuthToken.
// Returns nil, nil if no AuthToken is found for the token.  All options are ignored.
func (r *Repository) ValidateToken(ctx context.Context, id, token string, opt ...Option) (*AuthToken, error) {
	// Do not log or add the token string to any errors.
	if token == "" {
		return nil, fmt.Errorf("validate token: auth token: missing token: %w", db.ErrInvalidParameter)
	}
	retAT := allocAuthToken()
	retAT.PublicId = id

	var rowsUpdated int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := r.reader.LookupByPublicId(ctx, retAT); err != nil {
				return fmt.Errorf("validate token: lookup auth token: %s: %w", id, err)
			}

			// If the token is to old or stale invalidate it and return nothing.
			exp, err := ptypes.Timestamp(retAT.GetExpirationTime().GetTimestamp())
			if err != nil {
				return err
			}
			lastAccessed, err := ptypes.Timestamp(retAT.GetApproximateLastAccessTime().GetTimestamp())
			if err != nil {
				return err
			}

			now := time.Now()
			sinceLastAccessed := now.Sub(lastAccessed)
			if now.After(exp) || sinceLastAccessed > maxStaleness {
				metadata := newAuthTokenMetadata(retAT, oplog.OpType_OP_TYPE_DELETE)
				delAt := retAT.clone()
				if _, err := w.Delete(ctx, delAt, db.WithOplog(r.wrapper, metadata)); err != nil {
					return fmt.Errorf("validate token: delete auth token: %w", err)
				}
				retAT = nil
				return nil
			}

			if err := retAT.DecryptData(ctx, r.wrapper); err != nil {
				return err
			}
			if retAT.GetToken() != token {
				return db.ErrInvalidParameter
			}
			// retAT.Token set to empty string so the value is not returned as described in the methods' doc.
			retAT.Token = ""
			retAT.CtToken = nil

			if sinceLastAccessed < lastAccessedUpdateDuration {
				// To save the db from being updated to frequently, we only update the
				// LastAccessTime if it hasn't been updated within lastAccessedUpdateDuration.
				// TODO: Make this duration configurable.
				return nil
			}

			metadata := newAuthTokenMetadata(retAT, oplog.OpType_OP_TYPE_UPDATE)
			// Setting the ApproximateLastAccessTime to null through using the null mask allows a defined db's
			// trigger to set ApproximateLastAccessTime to the commit timestamp.
			at := retAT.clone()
			rowsUpdated, err = w.Update(
				ctx,
				at,
				nil,
				[]string{"ApproximateLastAccessTime"},
				db.WithOplog(r.wrapper, metadata),
			)
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return nil, fmt.Errorf("validate token: auth token: %s: %w", retAT.PublicId, err)
	}
	return retAT, nil
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
		if errors.Is(err, db.ErrRecordNotFound) {
			return db.NoRowsAffected, nil
		}
		return 0, fmt.Errorf("delete: auth token: lookup %w", err)
	}
	if at == nil {
		return db.NoRowsAffected, nil
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

// getUserWithIdAndAuthMethod returns a user only if the user with the provided id currently has the provided
// auth method and they are both in the same scope.  If that is not the case a nil iam.User will be returned.
func (r *Repository) getUserWithIdAndAuthMethod(withIamUserId, withAuthMethodId string, opt ...Option) (*iam.User, error) {
	if withAuthMethodId == "" {
		return nil, fmt.Errorf("missing auth method id %w", db.ErrInvalidParameter)
	}
	if withIamUserId == "" {
		return nil, fmt.Errorf("missing iam user id %w", db.ErrInvalidParameter)
	}
	underlying, err := r.reader.DB()
	if err != nil {
		return nil, fmt.Errorf("unable to get underlying db for auth account search: %w", err)
	}
	userTable := (&iam.User{}).TableName()
	acctTable := (&iam.AuthAccount{}).TableName()
	authMethodTable := "auth_method"

	q := fmt.Sprintf(`	
	select %[1]s.*
		from %[1]s 
	inner join %[2]s 
			on %[1]s.public_id = %[2]s.iam_user_id
	inner join %[3]s 
			on %[2]s.auth_method_id = %[3]s.public_id 
	where 
		%[1]s.scope_id = %[2]s.scope_id
		and %[2]s.scope_id = %[3]s.scope_id
		and %[1]s.public_id = $1
		and %[3]s.public_id = $2`, userTable, acctTable, authMethodTable)
	rows, err := underlying.Query(q, withIamUserId, withAuthMethodId)
	if err != nil {
		return nil, fmt.Errorf("unable to query iam user %s", withIamUserId)
	}
	defer rows.Close()
	u := &iam.User{User: &iamStore.User{}}
	if rows.Next() {
		err = r.reader.ScanRows(rows, u)
		if err != nil {
			return nil, fmt.Errorf("unable to scan rows for iam user %s, auth method %s: %w", withIamUserId, withAuthMethodId, err)
		}
	} else {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("unable to get next iam user: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to get next row for iam user %s, auth method %s: %w", withIamUserId, withAuthMethodId, err)
	}
	return u, nil
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
