// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetAddress    string `envconfig:"E2E_TARGET_ADDRESS" required:"true"` // e.g. 192.168.0.1
	TargetSshKeyPath string `envconfig:"E2E_SSH_KEY_PATH" required:"true"`   // e.g. /Users/username/key.pem
	TargetSshUser    string `envconfig:"E2E_SSH_USER" required:"true"`       // e.g. ubuntu
	TargetPort       string `envconfig:"E2E_TARGET_PORT" required:"true"`
	MaxPageSize      int    `envconfig:"E2E_MAX_PAGE_SIZE" default:"1000"`
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
