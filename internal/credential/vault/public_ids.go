package vault

import (
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(credential.Domain, Subtype, CredentialStorePrefix, CredentialLibraryPrefix, DynamicCredentialPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the vault package.
const (
	CredentialStorePrefix   = "csvlt"
	CredentialLibraryPrefix = "clvlt"
	DynamicCredentialPrefix = "cdvlt"

	Subtype = subtypes.Subtype("vault")
)

func newCredentialStoreId() (string, error) {
	id, err := db.NewPublicId(CredentialStorePrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "vault.newCredentialStoreId")
	}
	return id, nil
}

func newCredentialId() (string, error) {
	id, err := db.NewPublicId(DynamicCredentialPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "vault.newCredentialId")
	}
	return id, nil
}

func newCredentialLibraryId() (string, error) {
	id, err := db.NewPublicId(CredentialLibraryPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "vault.newCredentialLibraryId")
	}
	return id, nil
}
