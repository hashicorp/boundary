// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

func init() {
	kms.RegisterTableRewrapFn("host_plugin_catalog_secret", hostCatalogSecretRewrapFn)
}

func hostCatalogSecretRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "plugin.hostCatalogSecretRewrapFn"
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
	var secrets []*HostCatalogSecret
	// The only index on this table is on catalog id and there are no references to catalog id.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &secrets, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, secret := range secrets {
		if err := secret.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt host catalog secret"))
		}
		if err := secret.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt host catalog secret"))
		}
		if _, err := writer.Update(ctx, secret, []string{"CtSecret", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update host catalog secret row with rewrapped fields"))
		}
	}
	return nil
}
