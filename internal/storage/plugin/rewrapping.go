// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/storage/storagebucketcredential/managedsecret"
	"github.com/hashicorp/boundary/internal/util"
)

const (
	storageBucketCredentialManagedSecretTablename = "storage_bucket_credential_managed_secret"
)

func init() {
	kms.RegisterTableRewrapFn(storageBucketCredentialManagedSecretTablename, storageBucketCredentialRewrapFn)
}

// storageBucketCredentialRewrapFn provides a kms.Rewrapfn for the StorageBucketCredentialManagedSecret type
func storageBucketCredentialRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo kms.GetWrapperer) error {
	const op = "storage.storageBucketCredentialRewrapFn"
	switch {
	case dataKeyVersionId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing data key version id")
	case scopeId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case util.IsNil(reader):
		return errors.New(ctx, errors.InvalidParameter, op, "missing database reader")
	case util.IsNil(writer):
		return errors.New(ctx, errors.InvalidParameter, op, "missing database writer")
	case kmsRepo == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms repository")
	}
	var sbcms []*managedsecret.StorageBucketCredential
	// The only index on this table is on the primary key (storage bucket id) and we can't find it that way.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &sbcms, "key_id=?", []any{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query sql for rows that need rewrapping"))
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to fetch kms wrapper for rewrapping"))
	}
	for _, secret := range sbcms {
		if err := secret.Decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to decrypt storage bucket secret"))
		}
		if err := secret.Encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to re-encrypt storage bucket secret"))
		}
		if _, err := writer.Update(ctx, secret, []string{"CtSecrets", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update storage bucket secret row with rewrapped fields"))
		}
	}
	return nil
}
