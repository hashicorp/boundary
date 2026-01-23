// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_plus_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetAddress           string `envconfig:"E2E_TARGET_ADDRESS" required:"true"` // e.g. 192.168.0.1
	TargetSshKeyPath        string `envconfig:"E2E_SSH_KEY_PATH" required:"true"`   // e.g. /Users/username/key.pem
	TargetSshUser           string `envconfig:"E2E_SSH_USER" required:"true"`       // e.g. ubuntu
	TargetPort              string `envconfig:"E2E_TARGET_PORT" required:"true"`    // e.g. 22
	PostgresDbName          string `envconfig:"E2E_POSTGRES_DB_NAME" required:"true"`
	PostgresUser            string `envconfig:"E2E_POSTGRES_USER" required:"true"`
	PostgresPassword        string `envconfig:"E2E_POSTGRES_PASSWORD" required:"true"`
	PostgresAddress         string `envconfig:"E2E_POSTGRES_ADDRESS" required:"true"`
	PostgresPort            string `envconfig:"E2E_POSTGRES_PORT" required:"true"`
	LdapAddress             string `envconfig:"E2E_LDAP_ADDR" required:"true"`      // e.g. ldap://ldap
	LdapDomainDn            string `envconfig:"E2E_LDAP_DOMAIN_DN" required:"true"` // e.g. dc=example,dc=org
	LdapAdminDn             string `envconfig:"E2E_LDAP_ADMIN_DN" required:"true"`  // e.g. cn=admin,dc=example,dc=org
	LdapAdminPassword       string `envconfig:"E2E_LDAP_ADMIN_PASSWORD" required:"true"`
	LdapUserName            string `envconfig:"E2E_LDAP_USER_NAME" required:"true"`
	LdapUserPassword        string `envconfig:"E2E_LDAP_USER_PASSWORD" required:"true"`
	LdapGroupName           string `envconfig:"E2E_LDAP_GROUP_NAME" required:"true"`
	ControllerContainerName string `envconfig:"E2E_CONTROLLER_CONTAINER_NAME" required:"true"`
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
