package authtoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn(defaultAuthTokenTableName, authTokenRewrapFn)
}

func authTokenRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "authtoken.authTokenRewrapFn"
	var credentials []*AuthToken
	// Indexes exist on public id and token, and the only reference to public id is session, which may not exist for all rows we need.
	// This is the fastest query we can use without creating a new index on key_id.
	if err := reader.SearchWhere(ctx, &credentials, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
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
