package password

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/oplog"
	"golang.org/x/crypto/argon2"
)

type authAccount struct {
	*Account
	*Argon2Credential
	*Argon2Configuration
	IsCurrentConf bool
}

// Authenticate authenticates userName and password match for userName in
// authMethodId. The account for the userName is returned if authentication
// is successful. Returns nil if authentication fails.
//
// The CredentialId in the returned account represents a user's current
// password. A new CredentialId is generated when a user's password is
// changed and the old one is deleted.
//
// Authenticate will update the stored values for password to the current
// password settings for authMethodId if authentication is successful and
// the stored values are not using the current password settings.
func (r *Repository) Authenticate(ctx context.Context, authMethodId string, userName string, password string) (*Account, error) {
	if authMethodId == "" {
		return nil, fmt.Errorf("password authenticate: no authMethodId: %w", db.ErrInvalidParameter)
	}
	if userName == "" {
		return nil, fmt.Errorf("password authenticate: no userName: %w", db.ErrInvalidParameter)
	}
	if password == "" {
		return nil, fmt.Errorf("password authenticate: no password: %w", db.ErrInvalidParameter)
	}

	acct, err := r.authenticate(ctx, authMethodId, userName, password)
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

		// do not change the Credential Id
		cred.PrivateId = acct.CredentialId
		if err := cred.encrypt(ctx, r.wrapper); err != nil {
			return acct.Account, fmt.Errorf("password authenticate: update credential: encrypt: %w", err)
		}

		fields := []string{"CtSalt", "DerivedKey", "PasswordConfId"}
		metadata := cred.oplog(oplog.OpType_OP_TYPE_UPDATE)

		_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				rowsUpdated, err := w.Update(ctx, cred, fields, nil, db.WithOplog(r.wrapper, metadata))
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

// ChangePassword updates the password for userName in authMethodId to new
// if old equals the stored password. The account for the userName is
// returned with a new CredentialId if password is successfully changed.
//
// Returns nil if old does not match the stored password for userName.
// Returns ErrPasswordsEqual if old and new are equal.
func (r *Repository) ChangePassword(ctx context.Context, authMethodId string, userName string, old, new string) (*Account, error) {
	if authMethodId == "" {
		return nil, fmt.Errorf("change password: no authMethodId: %w", db.ErrInvalidParameter)
	}
	if userName == "" {
		return nil, fmt.Errorf("change password: no userName: %w", db.ErrInvalidParameter)
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

	acct, err := r.authenticate(ctx, authMethodId, userName, old)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	if acct == nil {
		return nil, nil
	}

	cc, err := r.currentConfig(ctx, authMethodId)
	if err != nil {
		return nil, fmt.Errorf("change password: retrieve current password configuration: %w", err)
	}
	if cc.MinPasswordLength > len(new) {
		return nil, fmt.Errorf("change password: %w", ErrTooShort)
	}
	newCred, err := newArgon2Credential(acct.PublicId, new, cc.argon2())
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}

	if err := newCred.encrypt(ctx, r.wrapper); err != nil {
		return nil, fmt.Errorf("change password: encrypt: %w", err)
	}

	oldCred := acct.Argon2Credential

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			rowsDeleted, err := w.Delete(ctx, oldCred, db.WithOplog(r.wrapper, oldCred.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			if err != nil {
				return err
			}
			return w.Create(ctx, newCred, db.WithOplog(r.wrapper, newCred.oplog(oplog.OpType_OP_TYPE_CREATE)))
		},
	)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}

	// change the Credential Id
	acct.Account.CredentialId = newCred.PrivateId
	return acct.Account, nil
}

func (r *Repository) authenticate(ctx context.Context, authMethodId string, userName string, password string) (*authAccount, error) {
	var accts []authAccount

	tx, err := r.reader.DB()
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(authenticateQuery, authMethodId, userName)
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

	if err := acct.decrypt(ctx, r.wrapper); err != nil {
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
func (r *Repository) SetPassword(ctx context.Context, accountId string, password string) error {
	if accountId == "" {
		return fmt.Errorf("set password: no accountId: %w", db.ErrInvalidParameter)
	}

	var newCred *Argon2Credential
	if password != "" {
		cc, err := r.currentConfigForAccount(ctx, accountId)
		if err != nil {
			return fmt.Errorf("set password: retrieve current configuration: %w", err)
		}
		if cc.MinPasswordLength > len(password) {
			return fmt.Errorf("set password: new password: %w", ErrTooShort)
		}
		newCred, err = newArgon2Credential(accountId, password, cc.argon2())
		if err != nil {
			return fmt.Errorf("set password: %w", err)
		}
		if err := newCred.encrypt(ctx, r.wrapper); err != nil {
			return fmt.Errorf("set password: encrypt: %w", err)
		}
	}

	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(rr db.Reader, w db.Writer) error {
			oldCred := allocCredential()
			if err := rr.LookupWhere(ctx, &oldCred, "password_account_id = ?", accountId); err != nil {
				if !errors.Is(err, db.ErrRecordNotFound) {
					return err
				}
			}
			if oldCred.PrivateId != "" {
				dCred := oldCred.clone()
				rowsDeleted, err := w.Delete(ctx, dCred, db.WithOplog(r.wrapper, oldCred.oplog(oplog.OpType_OP_TYPE_DELETE)))
				if err == nil && rowsDeleted > 1 {
					return db.ErrMultipleRecords
				}
				if err != nil {
					return err
				}
			}
			if newCred != nil {
				return w.Create(ctx, newCred, db.WithOplog(r.wrapper, newCred.oplog(oplog.OpType_OP_TYPE_CREATE)))
			}
			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	return nil
}
