package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(credential.Domain, Subtype, CredentialStorePrefix, PreviousCredentialStorePrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(credential.Domain, UsernamePasswordSubtype, CredentialPrefix, PreviousCredentialPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the static package.
const (
	CredentialStorePrefix         = "csst"
	PreviousCredentialStorePrefix = "cs"
	CredentialPrefix              = "credst"
	PreviousCredentialPrefix      = "cred"

	Subtype                 = subtypes.Subtype("static")
	UsernamePasswordSubtype = subtypes.Subtype("username_password")
)

func newCredentialStoreId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(CredentialStorePrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "static.newCredentialStoreId")
	}
	return id, nil
}

func newCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(CredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "static.newCredentialId")
	}
	return id, nil
}
