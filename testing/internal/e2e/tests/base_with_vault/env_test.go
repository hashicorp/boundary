// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package base_with_vault_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetIp         string `envconfig:"E2E_TARGET_IP" required:"true"`    // e.g. 192.168.0.1
	TargetSshUser    string `envconfig:"E2E_SSH_USER" required:"true"`     // e.g. ubuntu
	TargetSshKeyPath string `envconfig:"E2E_SSH_KEY_PATH" required:"true"` // e.g. /Users/username/key.pem
	TargetPort       string `envconfig:"E2E_SSH_PORT" required:"true"`
	// VaultAddr is the address that the Boundary server uses to interact with the running Vault instance
	VaultAddr       string `envconfig:"E2E_VAULT_ADDR" required:"true"` // e.g. "http://127.0.0.1:8200"
	VaultSecretPath string `envconfig:"E2E_VAULT_SECRET_PATH" default:"e2e_secrets"`
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
