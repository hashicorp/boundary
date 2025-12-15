// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_with_vault_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetAddress    string `envconfig:"E2E_TARGET_ADDRESS" required:"true"` // e.g. 192.168.0.1
	TargetSshUser    string `envconfig:"E2E_SSH_USER" required:"true"`       // e.g. ubuntu
	TargetSshKeyPath string `envconfig:"E2E_SSH_KEY_PATH" required:"true"`   // e.g. /Users/username/key.pem
	TargetPort       string `envconfig:"E2E_TARGET_PORT" required:"true"`    // e.g. 22
	// Note: Key is base64 encoded
	TargetCaKey string `envconfig:"E2E_SSH_CA_KEY" required:"true"`
	// VaultAddr is the address that the Boundary server uses to interact with the running Vault instance
	VaultAddr        string `envconfig:"E2E_VAULT_ADDR_PUBLIC" required:"true"`  // e.g. "http://127.0.0.1:8200"
	VaultAddrPrivate string `envconfig:"E2E_VAULT_ADDR_PRIVATE" required:"true"` // e.g. "http://10.10.10.10:8200"
	VaultSecretPath  string `envconfig:"E2E_VAULT_SECRET_PATH" default:"e2e_secrets"`
	VaultLdapPath    string `envconfig:"E2E_VAULT_LDAP_PATH" default:"e2e_ldap"`
	MaxPageSize      int    `envconfig:"E2E_MAX_PAGE_SIZE" default:"1000"`
	// Ldap configuration.
	LdapAddress       string `envconfig:"E2E_LDAP_ADDR" required:"true"`      // e.g. ldap://ldap
	LdapDomainDn      string `envconfig:"E2E_LDAP_DOMAIN_DN" required:"true"` // e.g. dc=example,dc=org
	LdapAdminDn       string `envconfig:"E2E_LDAP_ADMIN_DN" required:"true"`  // e.g. cn=admin,dc=example,dc=org
	LdapAdminPassword string `envconfig:"E2E_LDAP_ADMIN_PASSWORD" required:"true"`
	LdapUserName      string `envconfig:"E2E_LDAP_USER_NAME" required:"true"`
	LdapUserPassword  string `envconfig:"E2E_LDAP_USER_PASSWORD" required:"true"`
	LdapGroupName     string `envconfig:"E2E_LDAP_GROUP_NAME" required:"true"`
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
