package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn(defaultSessionTableName, sessionRewrapFn)
	kms.RegisterTableRewrapFn("session_credential", sessionCredentialRewrapFn)
}

func rewrapParameterChecks(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) string {
	if dataKeyVersionId == "" {
		return "missing data key version id"
	}
	if scopeId == "" {
		return "missing scope id"
	}
	if util.IsNil(reader) {
		return "missing database reader"
	}
	if util.IsNil(writer) {
		return "missing database writer"
	}
	if kmsRepo == nil {
		return "missing kms repository"
	}
	return ""
}

func sessionCredentialRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "session.sessionCredentialRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var creds []*credential
	// An index exists on (session_id, credential_sha256), so we can query workers via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, sessionCredentialRewrapQuery, []interface{}{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		cred := &credential{}
		if err := rows.Scan(
			&cred.SessionId,
			&cred.KeyId,
			&cred.CtCredential,
			&cred.CredentialSha256,
		); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to failed to scan row"))
		}
		creds = append(creds, cred)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to iterate over retrieved rows"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, cred := range creds {
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt session credential"))
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt session credential"))
		}
		if _, err := writer.Exec(ctx, sessionCredentialRewrapUpdate, []interface{}{
			cred.CtCredential,
			cred.KeyId,
			cred.SessionId,
			cred.CredentialSha256,
		}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update session credential row with rewrapped fields"))
		}
	}
	return nil
}

func sessionRewrapFn(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "session.sessionRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var sessions []*Session
	// An index exists on (project_id, user_id, termination_reason), so we can query sessions via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &sessions, "project_id=? and key_id=?", []interface{}{scopeId, dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	for _, session := range sessions {
		wrapper, err := kmsRepo.GetWrapper(ctx, session.GetProjectId(), kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
		}
		if err := session.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt session"))
		}
		if err := session.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt session"))
		}
		if _, err := writer.Update(ctx, session, []string{"CtTofuToken", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update session row with rewrapped fields"))
		}
	}
	return nil
}
