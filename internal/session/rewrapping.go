package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn("session_credential", sessionCredentialRewrapFn)
}

func sessionCredentialRewrapFn(ctx context.Context, dataKeyVersionId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "session.sessionCredentialRewrapFn"
	repo, err := NewRepository(ctx, reader, writer, kmsRepo, WithLimit(-1))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	var creds []*credential
	if err := repo.reader.SearchWhere(ctx, &creds, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, cred := range creds {
		session, _, err := repo.LookupSession(ctx, cred.SessionId)
		// check for session nil? technically shouldn't be possible according to db fk
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		wrapper, err := repo.kms.GetWrapper(ctx, session.GetProjectId(), kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := repo.writer.Exec(ctx, `
update session_credential
	set credential = ?,
		key_id = ?
where session_id = ?
	and credential_sha256 = ?;
		`, []interface{}{
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
