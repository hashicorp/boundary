package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn(defaultAuthMethodTableName, authMethodRewrapFn)
}

func authMethodRewrapFn(ctx context.Context, dataKeyVersionId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "oidc.authMethodRewrapFn"
	repo, err := NewRepository(ctx, reader, writer, kmsRepo)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	rows, err := repo.reader.Query(ctx, fmt.Sprintf(`select distinct scope_id from %q where key_id=?`, defaultAuthMethodTableName), []interface{}{dataKeyVersionId})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	var scopeIds []string
	for rows.Next() {
		var scopeId string
		if err := rows.Scan(&scopeId); err != nil {
			_ = rows.Close()
			return errors.Wrap(ctx, err, op)
		}
		scopeIds = append(scopeIds, scopeId)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, scopeId := range scopeIds {
		var authMethods []*AuthMethod
		if err := repo.reader.SearchWhere(ctx, &authMethods, "scope_id=? and key_id=?", []interface{}{scopeId, dataKeyVersionId}, db.WithLimit(-1)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		wrapper, err := repo.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		newKeyVersionId, err := wrapper.KeyId(ctx)
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
			am.KeyId = newKeyVersionId
			if _, err := repo.writer.Update(ctx, am, []string{CtClientSecretField, KeyIdField}, nil); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}
	return nil
}
