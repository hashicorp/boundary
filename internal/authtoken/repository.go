package authtoken

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
)

var (
	lastAccessedUpdateDuration = 10 * time.Minute
	timeSkew                   = time.Duration(0)
)

// A Repository stores and retrieves the persistent types in the authtoken
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader              db.Reader
	writer              db.Writer
	kms                 *kms.Kms
	limit               int
	timeToLiveDuration  time.Duration
	timeToStaleDuration time.Duration
}

// NewRepository creates a new Repository. The returned repository is not safe for concurrent go
// routines to access it.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "authtoken.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(errors.InvalidParameter, op, "nil db reader")
	case w == nil:
		return nil, errors.New(errors.InvalidParameter, op, "nil db writer")
	case kms == nil:
		return nil, errors.New(errors.InvalidParameter, op, "nil kms")
	}

	opts := getOpts(opt...)

	return &Repository{
		reader:              r,
		writer:              w,
		kms:                 kms,
		limit:               opts.withLimit,
		timeToLiveDuration:  opts.withTokenTimeToLiveDuration,
		timeToStaleDuration: opts.withTokenTimeToStaleDuration,
	}, nil
}

// CreateAuthToken inserts an Auth Token into the repository and returns a new
// Auth Token.  The returned auth token contains the auth token value. The
// provided IAM User ID must be associated to the provided auth account id or an
// error will be returned.  The Auth Token will have a Status of "issued".
// All options are ignored.
func (r *Repository) CreateAuthToken(ctx context.Context, withIamUser *iam.User, withAuthAccountId string, _ ...Option) (*AuthToken, error) {
	const op = "authtoken.(Repository).CreateAuthToken"
	if withIamUser == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing user")
	}
	if withIamUser.GetPublicId() == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing user id")
	}
	if withAuthAccountId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing auth account id")
	}
	at, err := newAuthToken()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	at.AuthAccountId = withAuthAccountId
	id, err := newAuthTokenId()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	at.PublicId = id

	databaseWrapper, err := r.kms.GetWrapper(ctx, withIamUser.GetScopeId(), kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}

	// We truncate the expiration time to the nearest second to make testing in different platforms with
	// different time resolutions easier.
	expiration, err := ptypes.TimestampProto(time.Now().Add(r.timeToLiveDuration).Truncate(time.Second))
	if err != nil {
		return nil, err
	}
	at.ExpirationTime = &timestamp.Timestamp{Timestamp: expiration}

	var newAuthToken *AuthToken
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			acct := allocAuthAccount()
			acct.PublicId = withAuthAccountId
			if err := read.LookupByPublicId(ctx, acct); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("auth account lookup"))
			}
			if acct.GetIamUserId() != withIamUser.GetPublicId() {
				return errors.New(errors.InvalidParameter, op,
					fmt.Sprintf("auth account %q mismatch with iam user %q", withAuthAccountId, withIamUser.GetPublicId()))
			}
			at.ScopeId = acct.GetScopeId()
			at.AuthMethodId = acct.GetAuthMethodId()
			at.IamUserId = acct.GetIamUserId()

			newAuthToken = at.clone()
			if err := newAuthToken.encrypt(ctx, databaseWrapper); err != nil {
				return err
			}
			// tokens are not replicated, so they don't need oplog entries.
			if err := w.Create(ctx, newAuthToken); err != nil {
				return err
			}
			newAuthToken.CtToken = nil

			return nil
		},
	)

	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return newAuthToken, nil
}

// LookupAuthToken returns the AuthToken for the provided id. Returns nil, nil if no AuthToken is found for id.
// For security reasons, the actual token is not included in the returned AuthToken.
// All exported options are ignored.
func (r *Repository) LookupAuthToken(ctx context.Context, id string, opt ...Option) (*AuthToken, error) {
	const op = "authtoken.(Repository).LookupAuthToken"
	if id == "" {
		return nil, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	opts := getOpts(opt...)

	// use the view, to bring in the required account columns. Just don't forget
	// to convert it before returning it.
	atv := allocAuthTokenView()
	atv.PublicId = id
	if err := r.reader.LookupByPublicId(ctx, atv); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op)
	}

	at := atv.toAuthToken()
	if opts.withTokenValue {
		databaseWrapper, err := r.kms.GetWrapper(ctx, at.GetScopeId(), kms.KeyPurposeDatabase, kms.WithKeyId(at.GetKeyId()))
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get database wrapper"))
		}
		if err := at.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(err, op)
		}
	}

	at.CtToken = nil
	at.KeyId = ""
	return at, nil
}

// ValidateToken returns a token from storage if the auth token with the provided id and token exists.  The
// approximate last accessed time may be updated depending on how long it has been since the last time the token
// was validated.  If a token is returned it is guaranteed to be valid. For security reasons, the actual token
// value is not included in the returned AuthToken. If no valid auth token is found nil, nil is returned.
// All options are ignored.
//
// NOTE: Do not log or add the token string to any errors to avoid leaking it as it is a secret.
func (r *Repository) ValidateToken(ctx context.Context, id, token string, opt ...Option) (*AuthToken, error) {
	const op = "authtoken.(Repository).ValidateToken"
	if token == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing token")
	}
	if id == "" {
		return nil, errors.New(errors.InvalidPublicId, op, "missing public id")
	}

	retAT, err := r.LookupAuthToken(ctx, id, withTokenValue())
	if err != nil {
		retAT = nil
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op)
	}
	if retAT == nil {
		return nil, nil
	}

	// If the token is too old or stale invalidate it and return nothing.
	exp, err := ptypes.Timestamp(retAT.GetExpirationTime().GetTimestamp())
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("expiration time"), errors.WithCode(errors.InvalidTimeStamp))
	}
	lastAccessed, err := ptypes.Timestamp(retAT.GetApproximateLastAccessTime().GetTimestamp())
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("last accessed time"), errors.WithCode(errors.InvalidTimeStamp))
	}

	now := time.Now()
	sinceLastAccessed := now.Sub(lastAccessed) + timeSkew
	// TODO (jimlambrt 9/2020) - investigate the need for the timeSkew and see
	// if it can be eliminated.
	if now.After(exp.Add(-timeSkew)) || sinceLastAccessed >= r.timeToStaleDuration {
		// If the token has expired or has become too stale, delete it from the DB.
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				delAt := retAT.clone()
				// tokens are not replicated, so they don't need oplog entries.
				if _, err := w.Delete(ctx, delAt); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("delete auth token"))
				}
				retAT = nil
				return nil
			})
		if err != nil {
			return nil, err
		}
		return nil, nil
	}

	if retAT.GetToken() != token {
		return nil, nil
	}
	// retAT.Token set to empty string so the value is not returned as described in the methods' doc.
	retAT.Token = ""

	if sinceLastAccessed >= lastAccessedUpdateDuration {
		// To save the db from being updated too frequently, we only update the
		// LastAccessTime if it hasn't been updated within lastAccessedUpdateDuration.
		// TODO: Make this duration configurable.
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				at := retAT.clone()
				// Setting the ApproximateLastAccessTime to null through using the null mask allows a defined db's
				// trigger to set ApproximateLastAccessTime to the commit
				// timestamp. Tokens are not replicated, so they don't need oplog entries.
				rowsUpdated, err := w.Update(
					ctx,
					at,
					nil,
					[]string{"ApproximateLastAccessTime"},
				)
				if err == nil && rowsUpdated > 1 {
					return errors.ErrMultipleRecords
				}
				return err
			},
		)
	}

	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(id))
	}
	return retAT, nil
}

// ListAuthTokens lists auth tokens in the given scopes and supports the
// WithLimit option.
func (r *Repository) ListAuthTokens(ctx context.Context, withScopeIds []string, opt ...Option) ([]*AuthToken, error) {
	const op = "authtoken.(Repository).ListAuthTokens"
	if len(withScopeIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)

	// use the view, to bring in the required account columns. Just don't forget
	// to convert them before returning them
	var atvs []*authTokenView
	if err := r.reader.SearchWhere(ctx, &atvs, "auth_account_id in (select public_id from auth_account where scope_id in (?))", []interface{}{withScopeIds}, db.WithLimit(opts.withLimit)); err != nil {
		return nil, errors.Wrap(err, op)
	}
	authTokens := make([]*AuthToken, 0, len(atvs))
	for _, atv := range atvs {
		atv.Token = ""
		atv.CtToken = nil
		atv.KeyId = ""
		authTokens = append(authTokens, atv.toAuthToken())
	}
	return authTokens, nil
}

// DeleteAuthToken deletes the token with the provided id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAuthToken(ctx context.Context, id string, opt ...Option) (int, error) {
	const op = "authtoken.(Repository).DeleteAuthToken"
	if id == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidPublicId, op, "missing public id")
	}

	at, err := r.LookupAuthToken(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return db.NoRowsAffected, nil
		}
		return db.NoRowsAffected, errors.Wrap(err, op)
	}
	if at == nil {
		return db.NoRowsAffected, nil
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteAT := at.clone()
			// tokens are not replicated, so they don't need oplog entries.
			rowsDeleted, err = w.Delete(ctx, deleteAT)
			if err == nil && rowsDeleted > 1 {
				return errors.ErrMultipleRecords
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(id))
	}

	return rowsDeleted, nil
}

// CreatePendingAuthToken creates a "pending" token in the repository using
// the tokenRequestId as it's PublicId. The provided IAM User ID must be
// associated to the provided auth account id or an error will be returned.  All
// options are ignored.
func (r *Repository) CreatePendingAuthToken(ctx context.Context, tokenRequestId string, iamUser *iam.User, withAuthAccountId string, opt ...Option) error {
	panic("to-do")
}

// IssueAuthToken will retrieve the "pending" token and update it's status to
// "issued".  If the token has already been issued, an error is returned with a
// nil token.  If no token is found for the tokenRequestId an error is returned
// with a nil token.
func (r *Repository) IssueAuthToken(ctx context.Context, tokenRequestId string) (*AuthToken, error) {
	panic("to-do")
}
