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

type accountAndScope struct {
	scopeId   string
	accountId string
}

func argon2ConfigRewrapFn(ctx context.Context, dataKeyVersionId string, reader db.Reader, writer db.Writer, kmsRepo *kms.Kms) error {
	const op = "password.argon2ConfigRewrapFn"
	repo, err := NewRepository(reader, writer, kmsRepo)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	rows, err := repo.reader.Query(
		ctx, `
select distinct acct.scope_id, acct.public_id
from auth_password_account acct
inner join auth_password_argon2_cred cred
on acct.public_id=cred.password_account_id
where cred.key_id=?
`,
		[]interface{}{dataKeyVersionId},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	var accounts []accountAndScope
	for rows.Next() {
		var account accountAndScope
		if err := rows.Scan(&account.scopeId, &account.accountId); err != nil {
			_ = rows.Close()
			return errors.Wrap(ctx, err, op)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, account := range accounts {
		var credentials []*Argon2Credential
		if err := repo.reader.SearchWhere(ctx, &credentials, "password_account_id=? and key_id=?", []interface{}{account.accountId, dataKeyVersionId}, db.WithLimit(-1)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		wrapper, err := repo.kms.GetWrapper(ctx, account.scopeId, kms.KeyPurposeDatabase)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		newKeyVersionId, err := wrapper.KeyId(ctx)
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
			cred.KeyId = newKeyVersionId
			if _, err := repo.writer.Update(ctx, cred, []string{"CtSalt", "KeyId"}, nil); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}
	return nil
}
