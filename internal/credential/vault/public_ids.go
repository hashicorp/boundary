// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(credential.Domain, Subtype, globals.VaultCredentialStorePrefix, globals.VaultDynamicCredentialPrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(credential.Domain, GenericLibrarySubtype, globals.VaultCredentialLibraryPrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(credential.Domain, SSHCertificateLibrarySubtype, globals.VaultSshCertificateCredentialLibraryPrefix); err != nil {
		panic(err)
	}
	globals.RegisterPrefixSubtype(globals.VaultCredentialStorePrefix, Subtype)
	globals.RegisterPrefixSubtype(globals.VaultDynamicCredentialPrefix, Subtype)
	globals.RegisterPrefixSubtype(globals.VaultCredentialLibraryPrefix, GenericLibrarySubtype)
	globals.RegisterPrefixSubtype(globals.VaultSshCertificateCredentialLibraryPrefix, SSHCertificateLibrarySubtype)
}

// PublicId prefixes for the resources in the vault package.
const (
	Subtype                      = globals.Subtype("vault")
	GenericLibrarySubtype        = globals.Subtype("vault-generic")
	SSHCertificateLibrarySubtype = globals.Subtype("vault-ssh-certificate")
)

func newCredentialStoreId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.VaultCredentialStorePrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "vault.newCredentialStoreId")
	}
	return id, nil
}

func newCredentialId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.VaultDynamicCredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "vault.newCredentialId")
	}
	return id, nil
}

func newCredentialLibraryId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.VaultCredentialLibraryPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "vault.newCredentialLibraryId")
	}
	return id, nil
}

func newSSHCertificateCredentialLibraryId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.VaultSshCertificateCredentialLibraryPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "vault.newSSHCertificateCredentialLibraryPrefix")
	}
	return id, nil
}
