// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package globals

// Subtype variables identify a boundary resource subtype.
type Subtype string

const (
	UnknownSubtype                    Subtype = ""
	PasswordSubtype                   Subtype = "password"
	OidcSubtype                       Subtype = "oidc"
	LdapSubtype                       Subtype = "ldap"
	StaticSubtype                     Subtype = "static"
	PluginSubtype                     Subtype = "plugin"
	VaultSubtype                      Subtype = "vault"
	VaultGenericLibrarySubtype        Subtype = "vault-generic"
	VaultSshCertificateLibrarySubtype Subtype = "vault-ssh-certificate"
	UsernamePasswordSubtype           Subtype = "username_password"
	SshPrivateKeySubtype              Subtype = "ssh_private_key"
	JsonSubtype                       Subtype = "json"
	TcpSubtype                        Subtype = "tcp"
	SshSubtype                        Subtype = "ssh"
)

// String returns the string representation of a Subtype
func (t Subtype) String() string {
	return string(t)
}
