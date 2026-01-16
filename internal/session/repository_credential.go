// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

// AddSessionCredentials encrypts the credData and adds the credentials to the repository. The credentials are linked
// to the sessionID provided, and encrypted using the sessProjectId. Session credentials are only valid for pending and
// active sessions, once a session ends, all session credentials are deleted.
// All options are ignored.
func (r *Repository) AddSessionCredentials(ctx context.Context, sessProjectId, sessionId string, credData []Credential, _ ...Option) error {
	const op = "session.(Repository).AddSessionCredentials"
	if sessionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if sessProjectId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session project id")
	}
	if len(credData) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing credentials")
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, sessProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	addCreds := make([]credential, 0, len(credData))
	for _, cred := range credData {
		if len(cred) == 0 {
			return errors.New(ctx, errors.InvalidParameter, op, "missing credential")
		}

		sessCred := credential{
			SessionId:  sessionId,
			Credential: cred,
		}
		if err := sessCred.encrypt(ctx, databaseWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to encrypt credential"))
		}
		addCreds = append(addCreds, sessCred)
	}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			if err := w.CreateItems(ctx, addCreds); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add session credentials"))
			}

			return nil
		},
	)
	return err
}

// ListSessionCredentials returns all Credential attached to the sessionId.
// All options are ignored.
func (r *Repository) ListSessionCredentials(ctx context.Context, sessProjectId, sessionId string, _ ...Option) ([]Credential, error) {
	const op = "session.(Repository).ListSessionCredentials"
	if sessionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if sessProjectId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing session project id")
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, sessProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	var creds []*credential
	if err := r.reader.SearchWhere(ctx, &creds, "session_id = ?", []any{sessionId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(creds) == 0 {
		return nil, nil
	}
	ret := make([]Credential, 0, len(creds))
	for _, c := range creds {
		if err := c.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to decrypt credential"))
		}
		ret = append(ret, c.Credential)
	}

	return ret, nil
}
