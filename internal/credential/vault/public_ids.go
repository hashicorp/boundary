// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.VaultCredentialStorePrefix, resource.CredentialStore, credential.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.VaultDynamicCredentialPrefix, resource.Credential, credential.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.VaultCredentialLibraryPrefix, resource.CredentialLibrary, credential.Domain, GenericLibrarySubtype)
	globals.RegisterPrefixToResourceInfo(globals.VaultSshCertificateCredentialLibraryPrefix, resource.CredentialLibrary, credential.Domain, SSHCertificateLibrarySubtype)
	globals.RegisterPrefixToResourceInfo(globals.VaultLdapCredentialLibraryPrefix, resource.CredentialLibrary, credential.Domain, LdapCredentialLibrarySubtype)
}

// PublicId prefixes for the resources in the vault package.
const (
	Subtype                      = globals.Subtype("vault")
	GenericLibrarySubtype        = globals.Subtype("vault-generic")
	SSHCertificateLibrarySubtype = globals.Subtype("vault-ssh-certificate")
	LdapCredentialLibrarySubtype = globals.Subtype("vault-ldap")
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

func newLdapCredentialLibraryId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.VaultLdapCredentialLibraryPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "vault.newLdapCredentialLibraryPrefix")
	}
	return id, nil
}
