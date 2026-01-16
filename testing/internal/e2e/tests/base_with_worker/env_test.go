// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_with_worker_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetAddress       string `envconfig:"E2E_TARGET_ADDRESS" required:"true"`        // e.g. 192.168.0.1
	TargetPort          string `envconfig:"E2E_TARGET_PORT" required:"true"`           // e.g. 22
	TargetSshUser       string `envconfig:"E2E_SSH_USER" required:"true"`              // e.g. ubuntu
	TargetSshKeyPath    string `envconfig:"E2E_SSH_KEY_PATH" required:"true"`          // e.g. /Users/username/key.pem
	WorkerTagIngress    string `envconfig:"E2E_WORKER_TAG_INGRESS" required:"true"`    // e.g. "ingress"
	WorkerTagEgress     string `envconfig:"E2E_WORKER_TAG_EGRESS" required:"true"`     // e.g. "egress"
	WorkerTagCollocated string `envconfig:"E2E_WORKER_TAG_COLLOCATED" required:"true"` // e.g. "collocated"
	// VaultAddr is the address that the Boundary server uses to interact with the running Vault instance
	VaultAddr        string `envconfig:"E2E_VAULT_ADDR_PUBLIC" required:"true"`  // e.g. "http://127.0.0.1:8200"
	VaultAddrPrivate string `envconfig:"E2E_VAULT_ADDR_PRIVATE" required:"true"` // e.g. "http://10.10.10.10:8200"
	VaultSecretPath  string `envconfig:"E2E_VAULT_SECRET_PATH" default:"e2e_secrets"`
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
