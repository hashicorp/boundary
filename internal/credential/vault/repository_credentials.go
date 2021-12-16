package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	vault "github.com/hashicorp/vault/api"
)

var _ credential.Issuer = (*Repository)(nil)

// Issue issues and returns dynamic credentials from Vault for all of the
// requests and assigns them to sessionId.
func (r *Repository) Issue(ctx context.Context, sessionId string, requests []credential.Request) ([]credential.Dynamic, error) {
	const op = "vault.(Repository).Issue"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no session id")
	}
	if len(requests) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no requests")
	}

	libs, err := r.getPrivateLibraries(ctx, requests)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// TODO(mgaffney)(ICU-1329) 05/2021: if any error occurs, mark all credentials
	// retrieved for revocation which will be handled by the revocation
	// job.

	var creds []credential.Dynamic
	var minLease time.Duration
	for _, lib := range libs {
		// Get the credential ID early. No need to get a secret from Vault
		// if there is no way to save it in the database.
		credId, err := newCredentialId()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		client, err := lib.client()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		var secret *vault.Secret
		switch Method(lib.HttpMethod) {
		case MethodGet:
			secret, err = client.get(lib.VaultPath)
		case MethodPost:
			secret, err = client.post(lib.VaultPath, lib.HttpRequestBody)
		default:
			return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unknown http method: library: %s", lib.PublicId))
		}

		if err != nil {
			// TODO(mgaffney) 05/2021: detect if the error is because of an
			// expired or invalid token
			return nil, errors.Wrap(ctx, err, op)
		}
		if secret == nil {
			return nil, errors.E(ctx, errors.WithCode(errors.VaultEmptySecret), errors.WithOp(op))
		}

		leaseDuration := time.Duration(secret.LeaseDuration) * time.Second
		if minLease > leaseDuration {
			minLease = leaseDuration
		}
		cred, err := newCredential(lib.GetPublicId(), sessionId, secret.LeaseID, lib.TokenHmac, leaseDuration)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		cred.PublicId = credId
		cred.IsRenewable = secret.Renewable

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

		creds = append(creds, &actualCredential{
			id:         cred.PublicId,
			sessionId:  cred.SessionId,
			lib:        lib,
			secretData: secret.Data,
			purpose:    lib.Purpose,
		})
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
