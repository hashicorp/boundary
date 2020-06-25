package password

import "context"

// Authenticate returns true and a CredentialID if password matches the
// password for userName in authMethodId.
//
// A CredentialID represents a user's current password. A new CredentialID
// is generated when a user's password is changed.
//
// Authenticate will update the stored values for password to the current
// password settings for authMethodId if authentication is successful and
// the stored values are not using the current password settings.
func (r *Repository) Authenticate(ctx context.Context, authMethodId string, userName string, password string) (bool, string, error) {
	panic("not implemented")
}

// ChangePassword updates the password for userName in authMethodId to new
// if old equals the stored password. Returns true and a CredentialID if
// password is successfully changed.
//
// Returns false if old does not match the stored password for userName.
func (r *Repository) ChangePassword(ctx context.Context, authMethodId string, userName string, old, new string) (bool, string, error) {
	panic("not implemented")
}
