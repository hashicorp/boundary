// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"

	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"golang.org/x/crypto/argon2"
)

type authAccount struct {
	*Account
	*Argon2Credential
	*Argon2Configuration
	IsCurrentConf bool
}

// Authenticate authenticates loginName and password match for loginName in
// authMethodId. The account for the loginName is returned if authentication
// is successful. Returns nil if authentication fails.
//
// The CredentialId in the returned account represents a user's current
// password. A new CredentialId is generated when a user's password is
// changed and the old one is deleted.
//
// Authenticate will update the stored values for password to the current
// password settings for authMethodId if authentication is successful and
// the stored values are not using the current password settings.
func (r *Repository) Authenticate(ctx context.Context, scopeId, authMethodId, loginName, password string) (*Account, error) {
	const op = "password.(Repository).Authenticate"
	if authMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing authMethodId", errors.WithoutEvent())
	}
	if loginName == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing loginName", errors.WithoutEvent())
	}
	if password == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password", errors.WithoutEvent())
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scopeId", errors.WithoutEvent())
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get database wrapper"))
	}

	acct, err := r.authenticate(ctx, scopeId, authMethodId, loginName, password)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if acct == nil {
		return nil, nil
	}

	if !acct.IsCurrentConf {
		cc, err := r.currentConfig(ctx, authMethodId)
		if err != nil {
			return acct.Account, errors.Wrap(ctx, err, op, errors.WithMsg("retrieve current password configuration"))
		}
		cred, err := newArgon2Credential(ctx, acct.PublicId, password, cc.argon2(), r.randomReader)
		if err != nil {
			return acct.Account, errors.Wrap(ctx, err, op, errors.WithCode(errors.PasswordInvalidConfiguration))
		}

		oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
		if err != nil {
			return acct.Account, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplong wrapper"))
		}

		// do not change the Credential Id
		cred.PrivateId = acct.CredentialId
		if err := cred.encrypt(ctx, databaseWrapper); err != nil {
			return acct.Account, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("update credential"))
		}

		fields := []string{"CtSalt", "DerivedKey", "PasswordConfId", "KeyId"}
		metadata := cred.oplog(oplog.OpType_OP_TYPE_UPDATE)

		_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				rowsUpdated, err := w.Update(ctx, cred, fields, nil, db.WithOplog(oplogWrapper, metadata))
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if rowsUpdated > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
				}
				return nil
			},
		)
		if err != nil {
			return acct.Account, errors.Wrap(ctx, err, op, errors.WithMsg("update credential"))
		}
	}
	return acct.Account, nil
}

// ChangePassword updates the password for accountId to new if old equals
// the stored password. The account for the accountId is returned with a
// new CredentialId if password is successfully changed.
//
// Returns nil, db.ErrorRecordNotFound if the account doesn't exist.
// Returns nil, nil if old does not match the stored password for accountId.
// Returns nil, error with code PasswordsEqual if old and new are equal.
func (r *Repository) ChangePassword(ctx context.Context, scopeId, accountId, old, new string, version uint32) (*Account, error) {
	const op = "password.(Repository).ChangePassword"
	if accountId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing account id")
	}
	if old == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing old password")
	}
	if new == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing new password")
	}
	if old == new {
		return nil, errors.New(ctx, errors.PasswordsEqual, op, "passwords must not equal")
	}
	if version == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scopeId")
	}

	authAccount, err := r.LookupAccount(ctx, accountId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if authAccount == nil {
		return nil, errors.New(ctx, errors.RecordNotFound, op, "account not found")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get database wrapper"))
	}

	acct, err := r.authenticate(ctx, scopeId, authAccount.GetAuthMethodId(), authAccount.GetLoginName(), old)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if acct == nil {
		return nil, nil
	}

	cc, err := r.currentConfig(ctx, authAccount.GetAuthMethodId())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("retrieve current password configuration"))
	}
	if cc.MinPasswordLength > len(new) {
		return nil, errors.New(ctx, errors.PasswordTooShort, op, fmt.Sprintf("must be at least %d", cc.MinPasswordLength))
	}
	newCred, err := newArgon2Credential(ctx, accountId, new, cc.argon2(), r.randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if err := newCred.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}

	oldCred := acct.Argon2Credential

	var updatedAccount *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			updatedAccount = allocAccount()
			updatedAccount.PublicId = accountId
			updatedAccount.Version = version + 1
			rowsUpdated, err := w.Update(ctx, updatedAccount, []string{"Version"}, nil, db.WithOplog(oplogWrapper, acct.Account.oplog(oplog.OpType_OP_TYPE_UPDATE)), db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update account version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated account and %d rows updated", rowsUpdated))
			}

			rowsDeleted, err := w.Delete(ctx, oldCred, db.WithOplog(oplogWrapper, oldCred.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			if err = w.Create(ctx, newCred, db.WithOplog(oplogWrapper, newCred.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create new credential"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// change the Credential Id
	updatedAccount.CredentialId = newCred.PrivateId
	return updatedAccount, nil
}

func (r *Repository) authenticate(ctx context.Context, scopeId, authMethodId, loginName, password string) (*authAccount, error) {
	const op = "password.(Repository).authenticate"
	var accts []authAccount

	rows, err := r.reader.Query(ctx, authenticateQuery, []any{sql.Named("auth_method_id", authMethodId), sql.Named("login_name", loginName)})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()
	for rows.Next() {
		var aa authAccount
		if err := r.reader.ScanRows(ctx, rows, &aa); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		accts = append(accts, aa)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var acct authAccount
	switch {
	case len(accts) == 0:
		return nil, nil
	case len(accts) > 1:
		// this should never happen
		return nil, errors.New(ctx, errors.Unknown, op, "multiple accounts returned for user name")
	default:
		acct = accts[0]
	}

	// We don't pass a wrapper in here because for ecryption we want to indicate the expected key ID
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase, kms.WithKeyId(acct.GetKeyId()))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get database wrapper"))
	}

	if err := acct.decrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("unable to decrypt credential"))
	}

	inputKey := argon2.IDKey([]byte(password), acct.Salt, acct.Iterations, acct.Memory, uint8(acct.Threads), acct.KeyLength)
	if subtle.ConstantTimeCompare(inputKey, acct.DerivedKey) == 0 {
		// authentication failed, password does not match
		return nil, nil
	}
	return &acct, nil
}

// SetPassword sets the password for accountId to password. If password
// contains an empty string, the password for accountId will be deleted.
func (r *Repository) SetPassword(ctx context.Context, scopeId, accountId, password string, version uint32) (*Account, error) {
	const op = "password.(Repository).SetPassword"
	if accountId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing accountId")
	}
	if version == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scopeId")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get database wrapper"))
	}

	var newCred *Argon2Credential
	if password != "" {
		cc, err := r.currentConfigForAccount(ctx, accountId)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if cc == nil {
			return nil, errors.New(ctx, errors.RecordNotFound, op, "unable to retrieve current configuration")
		}
		if cc.MinPasswordLength > len(password) {
			return nil, errors.New(ctx, errors.PasswordTooShort, op, fmt.Sprintf("password must be at least %v", cc.MinPasswordLength))
		}
		newCred, err = newArgon2Credential(ctx, accountId, password, cc.argon2(), r.randomReader)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if err := newCred.encrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
		}
	}

	var acct *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(rr db.Reader, w db.Writer) error {
			updatedAccount := allocAccount()
			updatedAccount.PublicId = accountId
			updatedAccount.Version = version + 1
			rowsUpdated, err := w.Update(ctx, updatedAccount, []string{"Version"}, nil, db.WithOplog(oplogWrapper, updatedAccount.oplog(oplog.OpType_OP_TYPE_UPDATE)), db.WithVersion(&version))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update account version"))
			}
			if rowsUpdated != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated account and %d rows updated", rowsUpdated))
			}
			acct = updatedAccount

			oldCred := allocCredential()
			if err := rr.LookupWhere(ctx, &oldCred, "password_account_id = ?", []any{accountId}); err != nil {
				if !errors.IsNotFoundError(err) {
					return errors.Wrap(ctx, err, op)
				}
			}
			if oldCred.PrivateId != "" {
				dCred := oldCred.clone()
				rowsDeleted, err := w.Delete(ctx, dCred, db.WithOplog(oplogWrapper, oldCred.oplog(oplog.OpType_OP_TYPE_DELETE)))
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if rowsDeleted > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
				}
			}
			if newCred != nil {
				return w.Create(ctx, newCred, db.WithOplog(oplogWrapper, newCred.oplog(oplog.OpType_OP_TYPE_CREATE)))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return acct, nil
}
