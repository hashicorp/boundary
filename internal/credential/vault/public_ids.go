// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(credential.Domain, Subtype, CredentialStorePrefix, DynamicCredentialPrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(credential.Domain, GenericLibrarySubtype, CredentialLibraryPrefix); err != nil {
		panic(err)
	}
	if err := subtypes.Register(credential.Domain, SSHCertificateLibrarySubtype, SSHCertificateCredentialLibraryPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the vault package.
const (
	CredentialStorePrefix                 = "csvlt"
	CredentialLibraryPrefix               = "clvlt"
	DynamicCredentialPrefix               = "cdvlt"
	SSHCertificateCredentialLibraryPrefix = "clvsclt"

	Subtype                      = subtypes.Subtype("vault")
	GenericLibrarySubtype        = subtypes.Subtype("vault-generic")
	SSHCertificateLibrarySubtype = subtypes.Subtype("vault-ssh-certificate")
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

func newSSHCertificateCredentialLibraryId() (string, error) {
	id, err := db.NewPublicId(SSHCertificateCredentialLibraryPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "vault.newSSHCertificateCredentialLibraryPrefix")
	}
	return id, nil
}
