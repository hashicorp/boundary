package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
)

var _ credential.Issuer = (*Repository)(nil)

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
		cred, err := lib.retrieveCredential(ctx, op, sessionId, opt...)
		if err != nil {
			return nil, err
		}

		if cred.getExpiration() < runJobsInterval {
			event.WriteError(ctx, op,
				fmt.Errorf("WARNING: credential will expire before job scheduler can run"),
				event.WithInfo("credential_public_id", cred.GetPublicId()),
				event.WithInfo("credential_library_public_id", lib.GetPublicId()),
				event.WithInfo("runJobsInterval", runJobsInterval),
			)
		}

		if minLease > cred.getExpiration() {
			minLease = cred.getExpiration()
		}
		insertQuery, insertQueryValues := cred.insertQuery()
		updateQuery, updateQueryValues := cred.updateSessionQuery(lib.Purpose)
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

		creds = append(creds, cred)
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
			if _, err := w.Exec(ctx, revokeCredentialsQuery, []interface{}{sessionId}); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	return err
}
