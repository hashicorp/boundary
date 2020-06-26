package password

import "context"

// Authenticate authenticates userName and password match for userName in
// authMethodId. The account for the userName is returned if authentication
// is successful. Returns nil if authentication fails.
//
// The CredentialID in the returned account represents a user's current
// password. A new CredentialID is generated when a user's password is
// changed and the old one is deleted.
//
// Authenticate will update the stored values for password to the current
// password settings for authMethodId if authentication is successful and
// the stored values are not using the current password settings.
func (r *Repository) Authenticate(ctx context.Context, authMethodId string, userName string, password string) (*Account, error) {
	panic("not implemented")
}

// ChangePassword updates the password for userName in authMethodId to new
// if old equals the stored password. The account for the userName is
// returned with a new CredentialID if password is successfully changed.
//
// Returns nil if old does not match the stored password for userName.
func (r *Repository) ChangePassword(ctx context.Context, authMethodId string, userName string, old, new string) (*Account, error) {
	panic("not implemented")
}
