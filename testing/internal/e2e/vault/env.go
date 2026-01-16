// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import "github.com/kelseyhightower/envconfig"

type config struct {
	// VaultAddr is the address that the Vault CLI uses to interact with the running Vault instance
	VaultAddr  string `envconfig:"VAULT_ADDR" required:"true"` // e.g. "http://127.0.0.1:8200"
	VaultToken string `envconfig:"VAULT_TOKEN" required:"true"`
}

func loadConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
