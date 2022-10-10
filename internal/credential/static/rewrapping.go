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

func credStaticUsernamePasswordRewrapFn(ctx context.Context, dataKeyVersionId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "static.credStaticUsernamePasswordRewrapFn"
	repo, err := NewRepository(ctx, reader, writer, kmsRepo, WithLimit(-1))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	var creds []*UsernamePasswordCredential
	if err := repo.reader.SearchWhere(ctx, &creds, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, cred := range creds {
		store, err := repo.LookupCredentialStore(ctx, cred.GetStoreId())
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		wrapper, err := repo.kms.GetWrapper(ctx, store.GetProjectId(), kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := repo.writer.Update(ctx, cred, []string{"CtPassword", "PasswordHmac", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func credStaticSshPrivKeyRewrapFn(ctx context.Context, dataKeyVersionId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "static.credStaticSshPrivKeyRewrapFn"
	repo, err := NewRepository(ctx, reader, writer, kmsRepo, WithLimit(-1))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	var creds []*SshPrivateKeyCredential
	if err := repo.reader.SearchWhere(ctx, &creds, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, cred := range creds {
		store, err := repo.LookupCredentialStore(ctx, cred.GetStoreId())
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		wrapper, err := repo.kms.GetWrapper(ctx, store.GetProjectId(), kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := repo.writer.Update(ctx, cred, []string{"PrivateKeyEncrypted", "PrivateKeyHmac", "PrivateKeyPassphraseEncrypted", "PrivateKeyPassphraseHmac", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
