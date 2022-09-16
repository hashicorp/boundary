package credential

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(Domain, UsernamePasswordSubtype, UsernamePasswordCredentialPrefix, PreviousUsernamePasswordCredentialPrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(Domain, SshPrivateKeySubtype, SshPrivateKeyCredentialPrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(Domain, JsonSubtype, JsonCredentialPrefix); err != nil {
		panic(err)
	}
}

const (
	UsernamePasswordCredentialPrefix         = "credup"
	PreviousUsernamePasswordCredentialPrefix = "cred"
	UsernamePasswordSubtype                  = subtypes.Subtype("username_password")

	SshPrivateKeyCredentialPrefix = "credspk"
	SshPrivateKeySubtype          = subtypes.Subtype("ssh_private_key")

	JsonCredentialPrefix = "credjson"
	JsonSubtype          = subtypes.Subtype("json")
)

func NewUsernamePasswordCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(UsernamePasswordCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewUsernamePasswordCredentialId")
	}
	return id, nil
}

func NewSshPrivateKeyCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(SshPrivateKeyCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewSshPrivateKeyCredentialId")
	}
	return id, nil
}

func NewJsonCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(JsonCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewJsonCredentialId")
	}
	return id, nil
}
