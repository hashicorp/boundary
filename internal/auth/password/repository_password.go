package password

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
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

	const (
		query = `
select acct.name,
       acct.description,
       acct.user_name,
       acct.public_id,
       acct.auth_method_id,
       acct.scope_id,
       acct.create_time,
       acct.update_time,
       cred.private_id as credential_id,
       cred.password_conf_id,
       cred.salt,
       cred.derived_key,
       conf.key_length,
       conf.iterations,
       conf.memory,
       conf.threads
  from auth_password_argon2_cred cred,
       auth_password_argon2_conf conf,
       auth_password_account acct
 where acct.auth_method_id = $1
   and acct.user_name = $2
   and cred.password_conf_id = conf.private_id
   and cred.password_account_id = acct.public_id;
`
	)

	type AuthAccount struct {
		*Account
		*Argon2Credential
		*Argon2Configuration
	}

	var accts []AuthAccount

	tx, err := r.reader.DB()
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(query, authMethodId, userName)
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

	// TODO(mgaffney) 07/2020: update stored credential if acct config is
	// not the current config for authMethodId
	return acct.Account, nil
}

// ChangePassword updates the password for userName in authMethodId to new
// if old equals the stored password. The account for the userName is
// returned with a new CredentialId if password is successfully changed.
//
// Returns nil if old does not match the stored password for userName.
func (r *Repository) ChangePassword(ctx context.Context, authMethodId string, userName string, old, new string) (*Account, error) {
	panic("not implemented")
}
