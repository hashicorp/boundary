package password

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// Prefixes for private ids for types in the password package.
const (
	argon2ConfigurationPrefix = "arg2conf"
	argon2CredentialPrefix    = "arg2cred"
)

func newArgon2ConfigurationId() (string, error) {
	const op = "password.newArgon2ConfigurationId"
	id, err := db.NewPrivateId(argon2ConfigurationPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newArgon2CredentialId() (string, error) {
	const op = "password.newArgon2CredentialId"
	id, err := db.NewPrivateId(argon2CredentialPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}
