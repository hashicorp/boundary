package password

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register("auth", Subtype, AuthMethodPrefix, intglobals.OldPasswordAccountPrefix, intglobals.NewPasswordAccountPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the password package.
const (
	AuthMethodPrefix = "ampw"

	Subtype = subtypes.Subtype("password")
)

func newAuthMethodId() (string, error) {
	const op = "password.newAuthMethodId"
	id, err := db.NewPublicId(AuthMethodPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newAccountId() (string, error) {
	const op = "password.newAccountId"
	id, err := db.NewPublicId(intglobals.NewPasswordAccountPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}
