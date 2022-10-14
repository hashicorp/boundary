package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn("host_plugin_catalog_secret", hostCatalogSecretRewrapFn)
}

func hostCatalogSecretRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "plugin.hostCatalogSecretRewrapFn"
	var secrets []*HostCatalogSecret
	// the only index on this table is on catalog id and there are no references to catalog id. this is the fastest query
	if err := reader.SearchWhere(ctx, &secrets, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, secret := range secrets {
		if err := secret.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := secret.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := writer.Update(ctx, secret, []string{"CtSecret", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
