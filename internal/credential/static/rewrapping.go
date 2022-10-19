package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn("credential_static_username_password_credential", credStaticUsernamePasswordRewrapFn)
	kms.RegisterTableRewrapFn("credential_static_ssh_private_key_credential", credStaticSshPrivKeyRewrapFn)
}

func credStaticUsernamePasswordRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "static.credStaticUsernamePasswordRewrapFn"
	var creds []*UsernamePasswordCredential
	// Indexes exist on public id, store id. neither of which are queryable via scope.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &creds, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, cred := range creds {
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt username/password credential"))
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt username/password credential"))
		}
		if _, err := writer.Update(ctx, cred, []string{"CtPassword", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update username/password credential row with rewrapped fields"))
		}
	}
	return nil
}

func credStaticSshPrivKeyRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "static.credStaticSshPrivKeyRewrapFn"
	var creds []*SshPrivateKeyCredential
	// Indexes exist on public id, store id. neither of which are queryable via scope.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &creds, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, cred := range creds {
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt ssh private key"))
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt ssh private key"))
		}
		if _, err := writer.Update(ctx, cred, []string{"PrivateKeyEncrypted", "PrivateKeyPassphraseEncrypted", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update ssh private key row with rewrapped fields"))
		}
	}
	return nil
}
