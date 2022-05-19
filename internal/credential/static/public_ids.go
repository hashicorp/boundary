package static

import (
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(credential.Domain, Subtype, CredentialStorePrefix, CredentialPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the static package.
const (
	CredentialStorePrefix = "cs"
	CredentialPrefix      = "cred"

	Subtype = subtypes.Subtype("static")
)

func newCredentialStoreId() (string, error) {
	id, err := db.NewPublicId(CredentialStorePrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "static.newCredentialStoreId")
	}
	return id, nil
}

func newCredentialId() (string, error) {
	id, err := db.NewPublicId(CredentialPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "static.newCredentialId")
	}
	return id, nil
}
