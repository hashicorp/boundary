// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn("credential_vault_client_certificate", credVaultClientCertificateRewrapFn)
	kms.RegisterTableRewrapFn("credential_vault_token", credVaultTokenRewrapFn)
}

func rewrapParameterChecks(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) string {
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

func credVaultClientCertificateRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "vault.credVaultClientCertificateRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var certs []*ClientCertificate
	// only index is store id, and store isn't queryable via scope.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &certs, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, cert := range certs {
		if err := cert.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt vault client certificate"))
		}
		if err := cert.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt vault client certificate"))
		}
		if _, err := writer.Update(ctx, cert, []string{"CtCertificateKey", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update vault client certificate row with rewrapped fields"))
		}
	}
	return nil
}

func credVaultTokenRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "vault.credVaultTokenRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var tokens []*Token
	// Indexes exist on token hmac, store id, expiration time. none of which are queryable via scope or key.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &tokens, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, token := range tokens {
		if err := token.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt vault token"))
		}
		if err := token.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt vault token"))
		}
		if _, err := writer.Update(ctx, token, []string{"CtToken", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update vault token row with rewrapped fields"))
		}
	}
	return nil
}
