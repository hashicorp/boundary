// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"google.golang.org/protobuf/types/known/timestamppb"
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
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "authtoken.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil db reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil db writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
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
// The WithStatus and WithPublicId options are supported and all other options
// are ignored.
func (r *Repository) CreateAuthToken(ctx context.Context, withIamUser *iam.User, withAuthAccountId string, opt ...Option) (*AuthToken, error) {
	const op = "authtoken.(Repository).CreateAuthToken"
	if withIamUser == nil || withIamUser.User == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user")
	}
	if withIamUser.GetPublicId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	if withAuthAccountId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth account id")
	}
	at, err := newAuthToken(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	at.AuthAccountId = withAuthAccountId
	opts := getOpts(opt...)
	if opts.withPublicId == "" {
		id, err := NewAuthTokenId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		opts.withPublicId = id
	}
	at.PublicId = opts.withPublicId

	switch {
	case opts.withStatus != "":
		at.Status = string(PendingStatus)
	default:
		at.Status = string(IssuedStatus)
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, withIamUser.GetScopeId(), kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	// We truncate the expiration time to the nearest second to make testing in different platforms with
	// different time resolutions easier.
	expiration := timestamppb.New(time.Now().Add(r.timeToLiveDuration).Truncate(time.Second))
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
				return errors.Wrap(ctx, err, op, errors.WithMsg("auth account lookup"))
			}
			if acct.GetIamUserId() != withIamUser.GetPublicId() {
				return errors.New(ctx, errors.InvalidParameter, op,
					fmt.Sprintf("auth account %q mismatch with iam user %q", withAuthAccountId, withIamUser.GetPublicId()))
			}
			at.ScopeId = acct.GetScopeId()
			at.AuthMethodId = acct.GetAuthMethodId()
			at.IamUserId = acct.GetIamUserId()

			newAuthToken = at.clone()
			if err := newAuthToken.encrypt(ctx, databaseWrapper); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// tokens are not replicated, so they don't need oplog entries.
			if err := w.Create(ctx, newAuthToken); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			newAuthToken.CtToken = nil

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return newAuthToken, nil
}

// LookupAuthToken returns the AuthToken for the provided id. Returns nil, nil if no AuthToken is found for id.
// For security reasons, the actual token is not included in the returned AuthToken.
// All exported options are ignored.
func (r *Repository) LookupAuthToken(ctx context.Context, id string, opt ...Option) (*AuthToken, error) {
	const op = "authtoken.(Repository).LookupAuthToken"
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
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
		return nil, errors.Wrap(ctx, err, op)
	}

	at := atv.toAuthToken()
	if opts.withTokenValue {
		databaseWrapper, err := r.kms.GetWrapper(ctx, at.GetScopeId(), kms.KeyPurposeDatabase, kms.WithKeyId(at.GetKeyId()))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get database wrapper"))
		}
		if err := at.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
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
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	}
	if id == "" {
		return nil, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}

	retAT, err := r.LookupAuthToken(ctx, id, withTokenValue())
	if err != nil {
		retAT = nil
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	if retAT == nil {
		return nil, nil
	}

	// If the token is too old or stale invalidate it and return nothing.
	exp := retAT.GetExpirationTime().AsTime()
	lastAccessed := retAT.GetApproximateLastAccessTime().AsTime()

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
					return errors.Wrap(ctx, err, op, errors.WithMsg("delete auth token"))
				}
				retAT = nil
				return nil
			})
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		return nil, nil
	}

	if subtle.ConstantTimeCompare([]byte(retAT.GetToken()), []byte(token)) == 0 {
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
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if rowsUpdated > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
				}
				return nil
			},
		)
	}

	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(id))
	}
	return retAT, nil
}

// listAuthTokens lists auth tokens in the given scopes and supports the
// WithLimit and WithStartPageAfterItem options.
func (r *Repository) listAuthTokens(ctx context.Context, withScopeIds []string, opt ...Option) ([]*AuthToken, time.Time, error) {
	const op = "authtoken.(Repository).listAuthTokens"
	if len(withScopeIds) == 0 {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)

	limit := r.limit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	args := []any{sql.Named("scope_ids", withScopeIds)}
	whereClause := "scope_id in @scope_ids"
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(create_time, public_id) < (@last_item_create_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("create_time desc, public_id desc")}
	return r.queryAuthTokens(ctx, whereClause, args, dbOpts...)
}

// listAuthTokensRefresh lists auth tokens in the given scopes and supports the
// WithLimit and WithStartPageAfterItem options.
func (r *Repository) listAuthTokensRefresh(ctx context.Context, updatedAfter time.Time, withScopeIds []string, opt ...Option) ([]*AuthToken, time.Time, error) {
	const op = "authtoken.(Repository).listAuthTokensRefresh"

	switch {
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")

	case len(withScopeIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	opts := getOpts(opt...)

	limit := r.limit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	args := []any{
		sql.Named("scope_ids", withScopeIds),
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
	}
	whereClause := "scope_id in @scope_ids and update_time > @updated_after_time"
	if opts.withStartPageAfterItem != nil {
		whereClause = fmt.Sprintf("(update_time, public_id) < (@last_item_update_time, @last_item_id) and %s", whereClause)
		args = append(args,
			sql.Named("last_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	dbOpts := []db.Option{db.WithLimit(limit), db.WithOrder("update_time desc, public_id desc")}
	return r.queryAuthTokens(ctx, whereClause, args, dbOpts...)
}

func (r *Repository) queryAuthTokens(ctx context.Context, whereClause string, args []any, opt ...db.Option) ([]*AuthToken, time.Time, error) {
	const op = "authtoken.(Repository).queryAuthTokens"

	var transactionTimestamp time.Time
	var authTokens []*AuthToken
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(rd db.Reader, w db.Writer) error {
		var atvs []*authTokenView
		err := rd.SearchWhere(ctx, &atvs, whereClause, args, opt...)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		authTokens = make([]*AuthToken, 0, len(atvs))
		for _, atv := range atvs {
			// Remove encrypted token value before converting
			atv.CtToken = nil
			authTokens = append(authTokens, atv.toAuthToken())
		}
		transactionTimestamp, err = rd.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return authTokens, transactionTimestamp, nil
}

// listDeletedIds lists the public IDs of any auth tokens deleted since the timestamp provided.
func (r *Repository) listDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "authtoken.(Repository).listDeletedIds"
	var deletedAuthTokens []*deletedAuthToken
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedAuthTokens, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted auth tokens"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var atIds []string
	for _, at := range deletedAuthTokens {
		atIds = append(atIds, at.PublicId)
	}
	return atIds, transactionTimestamp, nil
}

// estimatedCount returns an estimate of the total number of items in the auth tokens table.
func (r *Repository) estimatedCount(ctx context.Context) (int, error) {
	const op = "authtoken.(Repository).estimatedCount"
	rows, err := r.reader.Query(ctx, estimateCountAuthTokens, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total auth tokens"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total auth tokens"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total auth tokens"))
	}
	return count, nil
}

// DeleteAuthToken deletes the token with the provided id from the repository returning a count of the
// number of records deleted.  All options are ignored.
func (r *Repository) DeleteAuthToken(ctx context.Context, id string, opt ...Option) (int, error) {
	const op = "authtoken.(Repository).DeleteAuthToken"
	if id == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}

	at, err := r.LookupAuthToken(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return db.NoRowsAffected, nil
		}
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
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
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(id))
	}

	return rowsDeleted, nil
}

// IssueAuthToken will retrieve the "pending" token and update it's status to
// "issued".  If the token has already been issued, an error is returned with a
// nil token.  If no token is found for the tokenRequestId an error is returned
// with a nil token.
//
// Note: no oplog entries are created for auth token operations (this is intentional).
func (r *Repository) IssueAuthToken(ctx context.Context, tokenRequestId string) (*AuthToken, error) {
	const op = "authtoken.(Repository).IssueAuthToken"
	if tokenRequestId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token request id")
	}

	var at *AuthToken
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			at = allocAuthToken()
			at.PublicId = tokenRequestId
			at.Status = string(IssuedStatus)
			// note: no oplog operations are created for auth token operations (this is intentional).
			// Setting the ApproximateLastAccessTime to null through using the null mask allows a defined db's
			// trigger to set ApproximateLastAccessTime to the commit timestamp.
			rowsUpdated, err := w.Update(ctx, at, []string{"Status"}, []string{"ApproximateLastAccessTime"}, db.WithWhere("status = ?", PendingStatus))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithoutEvent())
			}
			if rowsUpdated == 0 {
				return errors.New(ctx, errors.RecordNotFound, op, "pending auth token not found")
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.Internal, op, fmt.Sprintf("should have updated 1 row and we attempted to update %d rows", rowsUpdated))
			}
			if at.Status != string(IssuedStatus) {
				return errors.New(ctx, errors.Internal, op, "updated auth token status != issued")
			}

			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
			}
			at, err = txRepo.LookupAuthToken(ctx, at.PublicId, withTokenValue())
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if at == nil {
				return errors.New(ctx, errors.RecordNotFound, op, "issued auth token not found")
			}
			return nil
		})
	if err != nil {
		return nil, err // error already wrapped when raised from r.DoTx(...)
	}
	return at, nil
}

// CloseExpiredPendingTokens will close expired pending tokens in the repo.
// This function should called on a periodic basis a Controllers via it's
// "ticker" pattern.
func (r *Repository) CloseExpiredPendingTokens(ctx context.Context) (int, error) {
	const op = "authtoken.(Repository).CloseExpiredPendingTokens"

	args := []any{string(FailedStatus), string(PendingStatus)}
	const sql = `update auth_token set status = ? where status = ? and now() > expiration_time`
	var tokensClosed int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			var err error
			tokensClosed, err = w.Exec(ctx, sql, args)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, err // error already wrapped when raised from r.DoTx(...)
	}
	return tokensClosed, nil
}
