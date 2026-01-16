// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn(defaultAuthTokenTableName, authTokenRewrapFn)
}

func authTokenRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "authtoken.authTokenRewrapFn"
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
	var credentials []*AuthToken
	// Indexes exist on public id and token, and the only reference to public id is session, which may not exist for all rows we need.
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
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt auth token"))
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt auth token"))
		}
		if _, err := writer.Update(ctx, cred, []string{"CtToken", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update auth token row with rewrapped fields"))
		}
	}
	return nil
}
