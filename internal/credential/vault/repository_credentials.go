// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
)

var _ credential.Issuer = (*Repository)(nil)

func insertQuery(c *Credential, sessionId string) (query string, queryValues []any) {
	queryValues = []any{
		sql.Named("public_id", c.PublicId),
		sql.Named("library_id", c.LibraryId),
		sql.Named("session_id", sessionId),
		sql.Named("token_hmac", c.TokenHmac),
		sql.Named("external_id", c.ExternalId),
		sql.Named("is_renewable", c.IsRenewable),
		sql.Named("status", c.Status),
		sql.Named("last_renewal_time", "now()"),
	}
	switch {
	case c.expiration == 0:
		query = insertCredentialWithInfiniteExpirationQuery
	default:
		query = insertCredentialWithExpirationQuery
		queryValues = append(queryValues, sql.Named("expiration_time", int(c.expiration.Round(time.Second).Seconds())))
	}
	return
}

func updateSessionQuery(c *Credential, sessionId string, purpose credential.Purpose) (query string, queryValues []any) {
	queryValues = []any{
		sql.Named("public_id", c.PublicId),
		sql.Named("library_id", c.LibraryId),
		sql.Named("session_id", sessionId),
		sql.Named("purpose", string(purpose)),
	}
	query = updateSessionCredentialQuery
	return
}

// Issue issues and returns dynamic credentials from Vault for all of the
// requests and assigns them to sessionId.
func (r *Repository) Issue(ctx context.Context, sessionId string, requests []credential.Request, opt ...credential.Option) ([]credential.Dynamic, error) {
	const op = "vault.(Repository).Issue"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no session id")
	}
	if len(requests) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no requests")
	}

	libs, err := r.getIssueCredLibraries(ctx, requests)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// TODO(mgaffney)(ICU-1329) 05/2021: if any error occurs, mark all credentials
	// retrieved for revocation which will be handled by the revocation
	// job.

	var creds []credential.Dynamic
	var minLease time.Duration
	runJobsInterval := r.scheduler.GetRunJobsInterval()
	for _, lib := range libs {
		cred, err := lib.retrieveCredential(ctx, op, opt...)
		if err != nil {
			return nil, err
		}

		creds = append(creds, cred)
		if !cred.isRevokable() {
			// No need to persist since the credential cannot be revoked nor renewed
			continue
		}

		if cred.getExpiration() < runJobsInterval {
			event.WriteError(ctx, op,
				fmt.Errorf("WARNING: credential will expire before job scheduler can run"),
				event.WithInfo("credential_public_id", cred.GetPublicId()),
				event.WithInfo("credential_library_public_id", lib.GetPublicId()),
				event.WithInfo("runJobsInterval", runJobsInterval.String()),
			)
		}

		if minLease > cred.getExpiration() {
			minLease = cred.getExpiration()
		}

		underlyingCred := cred.getCredential()

		insertQuery, insertQueryValues := insertQuery(underlyingCred, sessionId)
		if err != nil {
			return nil, err
		}
		updateQuery, updateQueryValues := updateSessionQuery(underlyingCred, sessionId, cred.Purpose())
		if err != nil {
			return nil, err
		}

		if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				rowsInserted, err := w.Exec(ctx, insertQuery, insertQueryValues)
				switch {
				case err != nil:
					return errors.Wrap(ctx, err, op)
				case rowsInserted > 1:
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 credential would have been inserted")
				}

				rowsUpdated, err := w.Exec(ctx, updateQuery, updateQueryValues)
				switch {
				case err != nil:
					return errors.Wrap(ctx, err, op)
				case rowsUpdated == 0:
					return errors.New(ctx, errors.InvalidDynamicCredential, op, "no matching dynamic credential for session found")
				case rowsUpdated > 1:
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 session credential would have been updated")
				}
				return nil
			},
		); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	// Best effort update next run time of credential renewal job, but an error should not
	// cause Issue to fail.
	// TODO (lcr 06/2021): log error once repo has logger
	_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, credentialRenewalJobName, minLease)

	return creds, nil
}

var _ credential.Revoker = (*Repository)(nil)

// Revoke revokes all dynamic credentials issued from Vault for sessionId.
func (r *Repository) Revoke(ctx context.Context, sessionId string) error {
	const op = "vault.(Repository).Revoke"
	if sessionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "no session id")
	}

	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			if _, err := w.Exec(ctx, revokeCredentialsQuery, []any{sessionId}); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	return err
}
