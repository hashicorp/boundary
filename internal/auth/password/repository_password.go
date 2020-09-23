package password

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
	if authMethodId == "" {
		return nil, fmt.Errorf("password authenticate: no authMethodId: %w", db.ErrInvalidParameter)
	}
	if loginName == "" {
		return nil, fmt.Errorf("password authenticate: no loginName: %w", db.ErrInvalidParameter)
	}
	if password == "" {
		return nil, fmt.Errorf("password authenticate: no password: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, fmt.Errorf("password authenticate: no scopeId: %w", db.ErrInvalidParameter)
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, fmt.Errorf("password authenticate: unable to get database wrapper: %w", err)
	}

	acct, err := r.authenticate(ctx, scopeId, authMethodId, loginName, password)
	if err != nil {
		return nil, fmt.Errorf("password authenticate: %w", err)
	}
	if acct == nil {
		return nil, nil
	}

	if !acct.IsCurrentConf {
		cc, err := r.currentConfig(ctx, authMethodId)
		if err != nil {
			return acct.Account, fmt.Errorf("password authenticate: retrieve current password configuration: %w", err)
		}
		cred, err := newArgon2Credential(acct.PublicId, password, cc.argon2())
		if err != nil {
			return acct.Account, fmt.Errorf("password authenticate: update credential: %w", err)
		}

		oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
		if err != nil {
			return acct.Account, fmt.Errorf("password authenticate: unable to get oplog wrapper: %w", err)
		}

		// do not change the Credential Id
		cred.PrivateId = acct.CredentialId
		if err := cred.encrypt(ctx, databaseWrapper); err != nil {
			return acct.Account, fmt.Errorf("password authenticate: update credential: encrypt: %w", err)
		}

		fields := []string{"CtSalt", "DerivedKey", "PasswordConfId"}
		metadata := cred.oplog(oplog.OpType_OP_TYPE_UPDATE)

		_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				rowsUpdated, err := w.Update(ctx, cred, fields, nil, db.WithOplog(oplogWrapper, metadata))
				if err == nil && rowsUpdated > 1 {
					return db.ErrMultipleRecords
				}
				return err
			},
		)
		if err != nil {
			return acct.Account, fmt.Errorf("password authenticate: update credential: %w", err)
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
// Returns nil, ErrPasswordsEqual if old and new are equal.
func (r *Repository) ChangePassword(ctx context.Context, scopeId, accountId, old, new string, version uint32) (*Account, error) {
	if accountId == "" {
		return nil, fmt.Errorf("change password: no account id: %w", db.ErrInvalidParameter)
	}
	if old == "" {
		return nil, fmt.Errorf("change password: no old password: %w", db.ErrInvalidParameter)
	}
	if new == "" {
		return nil, fmt.Errorf("change password: no new password: %w", db.ErrInvalidParameter)
	}
	if old == new {
		return nil, fmt.Errorf("change password: %w", ErrPasswordsEqual)
	}
	if version == 0 {
		return nil, fmt.Errorf("change password: no version supplied: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, fmt.Errorf("change password: no scopeId: %w", db.ErrInvalidParameter)
	}

	authAccount, err := r.LookupAccount(ctx, accountId)
	if err != nil {
		return nil, fmt.Errorf("change password: lookup account: %w", err)
	}
	if authAccount == nil {
		return nil, fmt.Errorf("change password: lookup account: account not found: %w", db.ErrRecordNotFound)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("change password: unable to get oplog wrapper: %w", err)
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, fmt.Errorf("change password: unable to get database wrapper: %w", err)
	}

	acct, err := r.authenticate(ctx, scopeId, authAccount.GetAuthMethodId(), authAccount.GetLoginName(), old)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	if acct == nil {
		return nil, nil
	}

	cc, err := r.currentConfig(ctx, authAccount.GetAuthMethodId())
	if err != nil {
		return nil, fmt.Errorf("change password: retrieve current password configuration: %w", err)
	}
	if cc.MinPasswordLength > len(new) {
		return nil, fmt.Errorf("change password: %w", ErrTooShort)
	}
	newCred, err := newArgon2Credential(accountId, new, cc.argon2())
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}

	if err := newCred.encrypt(ctx, databaseWrapper); err != nil {
		return nil, fmt.Errorf("change password: encrypt: %w", err)
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
				return fmt.Errorf("change password: unable to update account version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("change password: updated account and %d rows updated", rowsUpdated)
			}

			rowsDeleted, err := w.Delete(ctx, oldCred, db.WithOplog(oplogWrapper, oldCred.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			if err != nil {
				return err
			}
			return w.Create(ctx, newCred, db.WithOplog(oplogWrapper, newCred.oplog(oplog.OpType_OP_TYPE_CREATE)))
		},
	)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}

	// change the Credential Id
	updatedAccount.CredentialId = newCred.PrivateId
	return updatedAccount, nil
}

func (r *Repository) authenticate(ctx context.Context, scopeId, authMethodId, loginName, password string) (*authAccount, error) {
	var accts []authAccount

	tx, err := r.reader.DB()
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(authenticateQuery, authMethodId, loginName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var aa authAccount
		if err := r.reader.ScanRows(rows, &aa); err != nil {
			return nil, err
		}
		accts = append(accts, aa)
	}

	var acct authAccount
	switch {
	case len(accts) == 0:
		return nil, nil
	case len(accts) > 1:
		// this should never happen
		return nil, fmt.Errorf("multiple accounts returned for user name")
	default:
		acct = accts[0]
	}

	// We don't pass a wrapper in here because for ecryption we want to indicate the expected key ID
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase, kms.WithKeyId(acct.GetKeyId()))
	if err != nil {
		return nil, fmt.Errorf("unable to get database wrapper: %w", err)
	}

	if err := acct.decrypt(ctx, databaseWrapper); err != nil {
		return nil, fmt.Errorf("cannot decrypt credential: %w", err)
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
	if accountId == "" {
		return nil, fmt.Errorf("set password: no accountId: %w", db.ErrInvalidParameter)
	}
	if version == 0 {
		return nil, fmt.Errorf("set password: no version supplied: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, fmt.Errorf("set password: no scopeId: %w", db.ErrInvalidParameter)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, fmt.Errorf("set password: unable to get oplog wrapper: %w", err)
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, fmt.Errorf("set password: unable to get database wrapper: %w", err)
	}

	var newCred *Argon2Credential
	if password != "" {
		cc, err := r.currentConfigForAccount(ctx, accountId)
		if err != nil {
			return nil, fmt.Errorf("set password: retrieve current configuration: %w", err)
		}
		if cc == nil {
			return nil, fmt.Errorf("set password: retrieve current configuration: %w", db.ErrRecordNotFound)
		}
		if cc.MinPasswordLength > len(password) {
			return nil, fmt.Errorf("set password: new password: %w", ErrTooShort)
		}
		newCred, err = newArgon2Credential(accountId, password, cc.argon2())
		if err != nil {
			return nil, fmt.Errorf("set password: %w", err)
		}
		if err := newCred.encrypt(ctx, databaseWrapper); err != nil {
			return nil, fmt.Errorf("set password: encrypt: %w", err)
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
				return fmt.Errorf("set password: unable to update account version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("set password: updated account and %d rows updated", rowsUpdated)
			}
			acct = updatedAccount

			oldCred := allocCredential()
			if err := rr.LookupWhere(ctx, &oldCred, "password_account_id = ?", accountId); err != nil {
				if !errors.Is(err, db.ErrRecordNotFound) {
					return err
				}
			}
			if oldCred.PrivateId != "" {
				dCred := oldCred.clone()
				rowsDeleted, err := w.Delete(ctx, dCred, db.WithOplog(oplogWrapper, oldCred.oplog(oplog.OpType_OP_TYPE_DELETE)))
				if err == nil && rowsDeleted > 1 {
					return db.ErrMultipleRecords
				}
				if err != nil {
					return err
				}
			}
			if newCred != nil {
				return w.Create(ctx, newCred, db.WithOplog(oplogWrapper, newCred.oplog(oplog.OpType_OP_TYPE_CREATE)))
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("set password: %w", err)
	}
	return acct, nil
}
