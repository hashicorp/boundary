// Code generated by "make api"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package sessionrecordings

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

type VaultSSHCertificateCredentialLibraryAttributes struct {
	Path            string            `json:"path,omitempty"`
	Username        string            `json:"username,omitempty"`
	KeyType         string            `json:"key_type,omitempty"`
	KeyBits         uint32            `json:"key_bits,omitempty"`
	Ttl             string            `json:"ttl,omitempty"`
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty"`
}

func AttributesMapToVaultSSHCertificateCredentialLibraryAttributes(in map[string]interface{}) (*VaultSSHCertificateCredentialLibraryAttributes, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out VaultSSHCertificateCredentialLibraryAttributes
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &out,
		TagName: "json",
	})
	if err != nil {
		return nil, fmt.Errorf("error creating mapstructure decoder: %w", err)
	}
	if err := dec.Decode(in); err != nil {
		return nil, fmt.Errorf("error decoding: %w", err)
	}
	return &out, nil
}

func (pt *CredentialLibrary) GetVaultSSHCertificateCredentialLibraryAttributes() (*VaultSSHCertificateCredentialLibraryAttributes, error) {
	if pt.Type != "vault-ssh-certificate" {
		return nil, fmt.Errorf("asked to fetch %s-type attributes but credential-library is of type %s", "vault-ssh-certificate", pt.Type)
	}
	return AttributesMapToVaultSSHCertificateCredentialLibraryAttributes(pt.Attributes)
}
