// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn("credential_static_username_password_credential", credStaticUsernamePasswordRewrapFn)
	kms.RegisterTableRewrapFn("credential_static_ssh_private_key_credential", credStaticSshPrivKeyRewrapFn)
	kms.RegisterTableRewrapFn("credential_static_json_credential", credStaticJsonRewrapFn)
	kms.RegisterTableRewrapFn("credential_static_username_password_domain_credential", credStaticUsernamePasswordDomainRewrapFn)
	kms.RegisterTableRewrapFn("credential_static_password_credential", credStaticPasswordRewrapFn)
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

func credStaticUsernamePasswordRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "static.credStaticUsernamePasswordRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var creds []*UsernamePasswordCredential
	// Indexes exist on (store_id, etc), so we can query static stores via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, credStaticUsernamePasswordRewrapQuery, []any{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		cred := allocUsernamePasswordCredential()
		if err := rows.Scan(
			&cred.PublicId,
			&cred.CtPassword,
			&cred.KeyId,
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

func credStaticUsernamePasswordDomainRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "static.credStaticUsernamePasswordDomainRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var creds []*UsernamePasswordDomainCredential
	// Indexes exist on (store_id, etc), so we can query static stores via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, credStaticUsernamePasswordDomainRewrapQuery, []any{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		cred := allocUsernamePasswordDomainCredential()
		if err := rows.Scan(
			&cred.PublicId,
			&cred.CtPassword,
			&cred.KeyId,
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
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt username/password/domain credential"))
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt username/password/domain credential"))
		}
		if _, err := writer.Update(ctx, cred, []string{"CtPassword", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update username/password/domain credential row with rewrapped fields"))
		}
	}
	return nil
}

func credStaticPasswordRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "static.credStaticPasswordRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var creds []*PasswordCredential
	// Indexes exist on (store_id, etc), so we can query static stores via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, credStaticPasswordRewrapQuery, []any{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		cred := allocPasswordCredential()
		if err := rows.Scan(
			&cred.PublicId,
			&cred.CtPassword,
			&cred.KeyId,
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
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt password credential"))
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt password credential"))
		}
		if _, err := writer.Update(ctx, cred, []string{"CtPassword", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update password credential row with rewrapped fields"))
		}
	}
	return nil
}

func credStaticSshPrivKeyRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "static.credStaticSshPrivKeyRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var creds []*SshPrivateKeyCredential
	// Indexes exist on (store_id, etc), so we can query static stores via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, credStaticSshPrivKeyRewrapQuery, []any{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		cred := allocSshPrivateKeyCredential()
		if err := rows.Scan(
			&cred.PublicId,
			&cred.PrivateKeyEncrypted,
			&cred.PrivateKeyPassphraseEncrypted,
			&cred.KeyId,
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

func credStaticJsonRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "static.credStaticJsonRewrapFn"
	if errStr := rewrapParameterChecks(ctx, dataKeyVersionId, scopeId, reader, writer, kmsRepo); errStr != "" {
		return errors.New(ctx, errors.InvalidParameter, op, errStr)
	}
	var creds []*JsonCredential
	// Indexes exist on (store_id, etc), so we can query static stores via scope and refine with key id.
	// This is the fastest query we can use without creating a new index on key_id.
	rows, err := reader.Query(ctx, credStaticJsonRewrapQuery, []any{scopeId, dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	defer rows.Close()
	for rows.Next() {
		cred := allocJsonCredential()
		if err := rows.Scan(
			&cred.PublicId,
			&cred.ObjectEncrypted,
			&cred.KeyId,
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
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt json credential"))
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt json credential"))
		}
		if _, err := writer.Update(ctx, cred, []string{"ObjectEncrypted", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update json credential row with rewrapped fields"))
		}
	}
	return nil
}
