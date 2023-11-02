// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(Domain, UsernamePasswordSubtype, globals.UsernamePasswordCredentialPrefix, globals.UsernamePasswordCredentialPreviousPrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(Domain, SshPrivateKeySubtype, globals.SshPrivateKeyCredentialPrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(Domain, JsonSubtype, globals.JsonCredentialPrefix); err != nil {
		panic(err)
	}
	globals.RegisterPrefixSubtype(globals.UsernamePasswordCredentialPrefix, UsernamePasswordSubtype)
	globals.RegisterPrefixSubtype(globals.UsernamePasswordCredentialPreviousPrefix, UsernamePasswordSubtype)
	globals.RegisterPrefixSubtype(globals.SshPrivateKeyCredentialPrefix, SshPrivateKeySubtype)
	globals.RegisterPrefixSubtype(globals.JsonCredentialPrefix, JsonSubtype)
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
