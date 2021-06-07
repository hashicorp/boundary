package password

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// PublicId prefixes for the resources in the password package.
const (
	AuthMethodPrefix = "ampw"
	OldAccountPrefix = "apw"
	NewAccountPrefix = "acctpw"
)

func newAuthMethodId() (string, error) {
	const op = "password.newAuthMethodId"
	id, err := db.NewPublicId(AuthMethodPrefix)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}

func newAccountId() (string, error) {
	const op = "password.newAccountId"
	id, err := db.NewPublicId(NewAccountPrefix)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}
