package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn("credential_vault_client_certificate", credVaultClientCertificateRewrapFn)
	kms.RegisterTableRewrapFn("credential_vault_token", credVaultTokenRewrapFn)
}

func credVaultClientCertificateRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "vault.credVaultClientCertificateRewrapFn"
	var certs []*ClientCertificate
	// only index is store id, and store isn't queryable via scope. this is the fastest query
	if err := reader.SearchWhere(ctx, &certs, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, cert := range certs {
		if err := cert.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cert.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := writer.Update(ctx, cert, []string{"CtCertificateKey", "CertificateKeyHmac", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func credVaultTokenRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "vault.credVaultTokenRewrapFn"
	var tokens []*Token
	// indexes on token hmac, store id, expiration time. none of which are queryable via scope or key. this is the fastest query
	if err := reader.SearchWhere(ctx, &tokens, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, token := range tokens {
		if err := token.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := token.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := writer.Update(ctx, token, []string{"CtToken", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
