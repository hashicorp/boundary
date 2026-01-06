// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.UsernamePasswordCredentialPrefix, resource.Credential, Domain, UsernamePasswordSubtype)
	globals.RegisterPrefixToResourceInfo(globals.UsernamePasswordDomainCredentialPrefix, resource.Credential, Domain, UsernamePasswordDomainSubtype)
	globals.RegisterPrefixToResourceInfo(globals.UsernamePasswordCredentialPreviousPrefix, resource.Credential, Domain, UsernamePasswordSubtype)
	globals.RegisterPrefixToResourceInfo(globals.PasswordCredentialPrefix, resource.Credential, Domain, PasswordSubtype)
	globals.RegisterPrefixToResourceInfo(globals.SshPrivateKeyCredentialPrefix, resource.Credential, Domain, SshPrivateKeySubtype)
	globals.RegisterPrefixToResourceInfo(globals.JsonCredentialPrefix, resource.Credential, Domain, JsonSubtype)
}

const (
	UsernamePasswordSubtype = globals.Subtype("username_password")

	UsernamePasswordDomainSubtype = globals.Subtype("username_password_domain")

	PasswordSubtype = globals.Subtype("password")

	SshPrivateKeySubtype = globals.Subtype("ssh_private_key")

	JsonSubtype = globals.Subtype("json")
)

// NewUsernamePasswordCredentialId generates a new public ID for a username-password credential.
func NewUsernamePasswordCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.UsernamePasswordCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewUsernamePasswordCredentialId")
	}
	return id, nil
}

// NewUsernamePasswordDomainCredentialId creates a new public ID for a username-password-domain credential.
func NewUsernamePasswordDomainCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.UsernamePasswordDomainCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewUsernamePasswordDomainCredentialId")
	}
	return id, nil
}

// NewPasswordCredentialId generates a new public ID for a password credential.
func NewPasswordCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.PasswordCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewPasswordCredentialId")
	}
	return id, nil
}

// New SshPrivateKeyCredentialId generates a new public ID for an SSH private key credential.
func NewSshPrivateKeyCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.SshPrivateKeyCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewSshPrivateKeyCredentialId")
	}
	return id, nil
}

// NewJsonCredentialId creates a new public ID for a JSON credential.
func NewJsonCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.JsonCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewJsonCredentialId")
	}
	return id, nil
}
