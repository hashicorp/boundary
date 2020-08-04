package password

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"golang.org/x/crypto/argon2"
)

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

	type AuthAccount struct {
		*Account
		*Argon2Credential
		*Argon2Configuration
		IsCurrentConf bool
	}

	var accts []AuthAccount

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
		var aa AuthAccount
		if err := r.reader.ScanRows(rows, &aa); err != nil {
			return nil, err
		}
		accts = append(accts, aa)
	}

	var acct AuthAccount
	switch {
	case len(accts) == 0:
		return nil, nil
	case len(accts) > 1:
		// this should never happen
		return nil, fmt.Errorf("authenticate: multiple accounts returned for user name")
	default:
		acct = accts[0]
	}

	if err := acct.decrypt(ctx, r.wrapper); err != nil {
		return nil, fmt.Errorf("authenticate: credential: cannot decrypt value: %w", err)
	}

	inputKey := argon2.IDKey([]byte(password), acct.Salt, acct.Iterations, acct.Memory, uint8(acct.Threads), acct.KeyLength)
	if subtle.ConstantTimeCompare(inputKey, acct.DerivedKey) == 0 {
		return nil, nil
	}

	if !acct.IsCurrentConf {
		cc, err := r.currentConfig(ctx, authMethodId)
		if err != nil {
			return acct.Account, fmt.Errorf("authenticate: retrieve current password configuration: %w", err)
		}
		cred, err := newArgon2Credential(acct.PublicId, password, cc.argon2())
		if err != nil {
			return acct.Account, fmt.Errorf("authenticate: rehash current password: %w", err)
		}
		cred.PrivateId = acct.CredentialId
		cred.PasswordMethodId = cc.PasswordMethodId

		var newCred *Argon2Credential
		_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				newCred = cred.clone()
				if err := newCred.encrypt(ctx, r.wrapper); err != nil {
					return err
				}
				rowsUpdated, err := w.Update(
					ctx,
					newCred,
					[]string{"CtSalt", "DerivedKey", "PasswordConfId"},
					nil,
					db.WithOplog(r.wrapper, cred.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				)
				if err == nil && rowsUpdated > 1 {
					return db.ErrMultipleRecords
				}
				return err
			},
		)
		if err != nil {
			return acct.Account, fmt.Errorf("authenticate: update rehashed password: %w", err)
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

	// authenticate
	type AuthAccount struct {
		*Account
		*Argon2Credential
		*Argon2Configuration
		IsCurrentConf bool
	}

	var accts []AuthAccount

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
		var aa AuthAccount
		if err := r.reader.ScanRows(rows, &aa); err != nil {
			return nil, err
		}
		accts = append(accts, aa)
	}

	var acct AuthAccount
	switch {
	case len(accts) == 0:
		return nil, nil
	case len(accts) > 1:
		// this should never happen
		return nil, fmt.Errorf("change password: multiple accounts returned for user name")
	default:
		acct = accts[0]
	}

	if err := acct.decrypt(ctx, r.wrapper); err != nil {
		return nil, fmt.Errorf("change password: credential: cannot decrypt value: %w", err)
	}

	inputKey := argon2.IDKey([]byte(old), acct.Salt, acct.Iterations, acct.Memory, uint8(acct.Threads), acct.KeyLength)
	if subtle.ConstantTimeCompare(inputKey, acct.DerivedKey) == 0 {
		return nil, nil
	}

	currentCred := acct.Argon2Credential
	currentCred.PrivateId = acct.CredentialId

	cc, err := r.currentConfig(ctx, authMethodId)
	if err != nil {
		return nil, fmt.Errorf("change password: retrieve current password configuration: %w", err)
	}
	if cc.MinPasswordLength > len(new) {
		return nil, fmt.Errorf("change password: %w", ErrTooShort)
	}
	cred, err := newArgon2Credential(acct.PublicId, new, cc.argon2())
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	cred.PasswordMethodId = cc.PasswordMethodId

	var oldCred, newCred *Argon2Credential
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			oldCred = currentCred.clone()
			rowsDeleted, err := w.Delete(ctx, oldCred, db.WithOplog(r.wrapper, currentCred.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			if err != nil {
				return err
			}
			newCred = cred.clone()
			if err := newCred.encrypt(ctx, r.wrapper); err != nil {
				return err
			}
			return w.Create(ctx, newCred, db.WithOplog(r.wrapper, cred.oplog(oplog.OpType_OP_TYPE_CREATE)))
		},
	)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}

	act := acct.Account
	act.CredentialId = newCred.PrivateId
	return act, nil
}
