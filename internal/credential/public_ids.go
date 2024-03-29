// Copyright (c) HashiCorp, Inc.
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
	globals.RegisterPrefixToResourceInfo(globals.UsernamePasswordCredentialPreviousPrefix, resource.Credential, Domain, UsernamePasswordSubtype)
	globals.RegisterPrefixToResourceInfo(globals.SshPrivateKeyCredentialPrefix, resource.Credential, Domain, SshPrivateKeySubtype)
	globals.RegisterPrefixToResourceInfo(globals.JsonCredentialPrefix, resource.Credential, Domain, JsonSubtype)
}

const (
	UsernamePasswordSubtype = globals.Subtype("username_password")

	SshPrivateKeySubtype = globals.Subtype("ssh_private_key")

	JsonSubtype = globals.Subtype("json")
)

func NewUsernamePasswordCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.UsernamePasswordCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewUsernamePasswordCredentialId")
	}
	return id, nil
}

func NewSshPrivateKeyCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.SshPrivateKeyCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewSshPrivateKeyCredentialId")
	}
	return id, nil
}

func NewJsonCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.JsonCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "credential.NewJsonCredentialId")
	}
	return id, nil
}
