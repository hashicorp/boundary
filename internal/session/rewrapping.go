package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn(defaultSessionTableName, sessionRewrapFn)
	kms.RegisterTableRewrapFn("session_credential", sessionCredentialRewrapFn)
}

func sessionCredentialRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "session.sessionCredentialRewrapFn"
	var creds []*credential
	// an index exists on (session_id, credential_sha256), so we can query workers via scope and refine with key id. this is the fastest query
	rows, err := reader.Query(ctx, sessionCredentialRewrapQuery, []interface{}{dataKeyVersionId, scopeId})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for rows.Next() {
		cred := &credential{}
		if err := rows.Scan(
			&cred.SessionId,
			&cred.KeyId,
			&cred.CtCredential,
			&cred.CredentialSha256,
		); err != nil {
			_ = rows.Close()
			return errors.Wrap(ctx, err, op)
		}
		creds = append(creds, cred)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, cred := range creds {
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := writer.Exec(ctx, sessionCredentialRewrapUpdate, []interface{}{
			cred.CtCredential,
			cred.KeyId,
			cred.SessionId,
			cred.CredentialSha256,
		}); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func sessionRewrapFn(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "session.sessionRewrapFn"
	var sessions []*Session
	// an index exists on (project_id, user_id, termination_reason), so we can query sessions via scope and refine with key id. this is the fastest query
	if err := reader.SearchWhere(ctx, &sessions, "project_id=? and key_id=?", []interface{}{scopeId, dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, session := range sessions {
		wrapper, err := kmsRepo.GetWrapper(ctx, session.GetProjectId(), kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := session.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := session.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := writer.Update(ctx, session, []string{"CtTofuToken", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
