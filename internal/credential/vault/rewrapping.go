package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

func init() {
	kms.RegisterTableRewrapFn("credential_vault_client_certificate", credVaultClientCertificateRewrapFn)
}

func credVaultClientCertificateRewrapFn(ctx context.Context, dataKeyVersionId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "vault.credVaultClientCertificateRewrapFn"
	// using an empty scheduler here since the only function we need is a lookup func and we really don't want to actually schedule something
	repo, err := NewRepository(reader, writer, kmsRepo, &scheduler.Scheduler{})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	var certs []*ClientCertificate
	if err := repo.reader.SearchWhere(ctx, &certs, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, cert := range certs {
		store, err := repo.LookupCredentialStore(ctx, cert.GetStoreId())
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		wrapper, err := repo.kms.GetWrapper(ctx, store.GetProjectId(), kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cert.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cert.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := repo.writer.Update(ctx, cert, []string{"CtCertificateKey", "CertificateKeyHmac", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
