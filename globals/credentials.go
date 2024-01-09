// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package globals

// CredentialType is a type of credential
type CredentialType string

// Credential type values.
const (
	UnspecifiedCredentialType      CredentialType = "unspecified"
	UsernamePasswordCredentialType CredentialType = "username_password"
	SshPrivateKeyCredentialType    CredentialType = "ssh_private_key"
	SshCertificateCredentialType   CredentialType = "ssh_certificate"
	JsonCredentialType             CredentialType = "json"
)
