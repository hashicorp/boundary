package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn(defaultAuthMethodTableName, authMethodRewrapFn)
}

func authMethodRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "oidc.authMethodRewrapFn"
	var authMethods []*AuthMethod
	// there are indexes on (scope id, <other>), so we can query on scope and refine via key id. this is the fastest query
	if err := reader.SearchWhere(ctx, &authMethods, "scope_id=? and key_id=?", []interface{}{scopeId, dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, am := range authMethods {
		if err := am.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := am.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := writer.Update(ctx, am, []string{CtClientSecretField, ClientSecretHmacField, KeyIdField}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
