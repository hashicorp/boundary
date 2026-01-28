// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn("auth_password_argon2_cred", argon2ConfigRewrapFn)
}

func argon2ConfigRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "password.argon2ConfigRewrapFn"
	if dataKeyVersionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing data key version id")
	}
	if scopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if util.IsNil(reader) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing database reader")
	}
	if util.IsNil(writer) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing database writer")
	}
	if kmsRepo == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms repository")
	}
	var credentials []*Argon2Credential
	// The only index on this table is on private id and there are no references to private id.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &credentials, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, cred := range credentials {
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt argon2 config"))
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt argon2 config"))
		}
		if _, err := writer.Update(ctx, cred, []string{"CtSalt", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update argon2 config row with rewrapped fields"))
		}
	}
	return nil
}
