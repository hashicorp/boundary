package password

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
)

func init() {
	kms.RegisterTableRewrapFn("auth_password_argon2_cred", argon2ConfigRewrapFn)
}

func argon2ConfigRewrapFn(ctx context.Context, dataKeyVersionId, scopeId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "password.argon2ConfigRewrapFn"
	var credentials []*Argon2Credential
	// the only index on this table is on private id and there are no references to private id. this is the fastest query
	if err := reader.SearchWhere(ctx, &credentials, "key_id=?", []interface{}{dataKeyVersionId}, db.WithLimit(-1)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	wrapper, err := kmsRepo.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, cred := range credentials {
		if err := cred.decrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := cred.encrypt(ctx, wrapper); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if _, err := writer.Update(ctx, cred, []string{"CtSalt", "KeyId"}, nil); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
