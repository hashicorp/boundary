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
		return nil, errors.New(errors.InvalidParameter, op, "no session id")
	}
	if len(requests) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no requests")
	}

	mapper := newMapper(requests)
	if mapper.Err() != nil {
		return nil, errors.Wrap(mapper.Err(), op)
	}

	libs, err := r.getPrivateLibraries(ctx, mapper.LibIds())
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	purpLibs := mapper.Map(libs)
	if mapper.Err() != nil {
		return nil, errors.Wrap(mapper.Err(), op)
	}

	// TODO(mgaffney)(ICU-1329) 05/2021: if any error occurs, mark all credentials
	// retrieved for revocation which will be handled by the revocation
	// job.

	var creds []credential.Dynamic
	for _, lib := range purpLibs {
		// Get the credential ID early. No need to get a secret from Vault
		// if there is no way to save it in the database.
		credId, err := newCredentialId()
		if err != nil {
			return nil, errors.Wrap(err, op)
		}

		client, err := lib.client()
		if err != nil {
			return nil, errors.Wrap(err, op)
		}

		var secret *vault.Secret
		switch Method(lib.HttpMethod) {
		case MethodGet:
			secret, err = client.get(lib.VaultPath)
		case MethodPost:
			secret, err = client.post(lib.VaultPath, lib.HttpRequestBody)
		default:
			return nil, errors.New(errors.Internal, op, fmt.Sprintf("unknown http method: library: %s", lib.PublicId))
		}

		if err != nil {
			// TODO(mgaffney) 05/2021: detect if the error is because of an
			// expired or invalid token
			return nil, errors.Wrap(err, op)
		}

		cred, err := newCredential(lib.GetPublicId(), sessionId, secret.LeaseID, lib.TokenHmac, time.Duration(secret.LeaseDuration)*time.Second)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		cred.PublicId = credId
		cred.IsRenewable = secret.Renewable

		insertQuery, insertQueryValues := cred.insertQuery()
		updateQuery, updateQueryValues := cred.updateSessionQuery(lib.Purpose)
		if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				rowsInserted, err := w.Exec(ctx, insertQuery, insertQueryValues)
				switch {
				case err == nil && rowsInserted > 1:
					return errors.New(errors.MultipleRecords, op, "more than 1 credential would have been inserted")
				case err != nil:
					return errors.Wrap(err, op)
				}

				rowsUpdated, err := w.Exec(ctx, updateQuery, updateQueryValues)
				switch {
				case err == nil && rowsUpdated == 0:
					return errors.New(errors.InvalidDynamicCredential, op, "no matching dynamic credential for session found")
				case err == nil && rowsUpdated > 1:
					return errors.New(errors.MultipleRecords, op, "more than 1 session credential would have been updated")
				case err != nil:
					return errors.Wrap(err, op)
				}
				return nil
			},
		); err != nil {
			return nil, errors.Wrap(err, op)
		}

		creds = append(creds, &privateCredential{
			id:         cred.PublicId,
			sessionId:  cred.SessionId,
			lib:        lib.privateLibrary,
			secretData: secret.Data,
			purpose:    lib.Purpose,
		})
	}

	return creds, nil
}
