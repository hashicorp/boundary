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
	// indexes on public id, store id. neither of which are queryable via scope. this is the fastest query
	if err := reader.SearchWhere(ctx, &creds, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
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
		if _, err := writer.Update(ctx, cred, []string{"CtPassword", "PasswordHmac", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func credStaticSshPrivKeyRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "static.credStaticSshPrivKeyRewrapFn"
	var creds []*SshPrivateKeyCredential
	if err := reader.SearchWhere(ctx, &creds, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
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
		if _, err := writer.Update(ctx, cred, []string{"PrivateKeyEncrypted", "PrivateKeyHmac", "PrivateKeyPassphraseEncrypted", "PrivateKeyPassphraseHmac", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
