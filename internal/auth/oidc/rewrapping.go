// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn(defaultAuthMethodTableName, authMethodRewrapFn)
}

func authMethodRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "oidc.authMethodRewrapFn"
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
	var authMethods []*AuthMethod
	// There are indexes on (scope id, <other>), so we can query on scope and refine via key id.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &authMethods, "scope_id=? and key_id=?", []any{scopeId, dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, am := range authMethods {
		if err := am.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt auth method"))
		}
		if err := am.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt auth method"))
		}
		if _, err := writer.Update(ctx, am, []string{CtClientSecretField, KeyIdField}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update auth method row with rewrapped fields"))
		}
	}
	return nil
}
