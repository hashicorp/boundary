// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package globals

// CredentialType is a type of credential
type CredentialType string

// Credential type values.
const (
	UnspecifiedCredentialType            CredentialType = "unspecified"
	UsernamePasswordCredentialType       CredentialType = "username_password"
	UsernamePasswordDomainCredentialType CredentialType = "username_password_domain"
	PasswordCredentialType               CredentialType = "password"
	SshPrivateKeyCredentialType          CredentialType = "ssh_private_key"
	SshCertificateCredentialType         CredentialType = "ssh_certificate"
	JsonCredentialType                   CredentialType = "json"
)
