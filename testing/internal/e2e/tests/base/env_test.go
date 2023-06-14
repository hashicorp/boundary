// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package base_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetIp         string `envconfig:"E2E_TARGET_IP" required:"true"`    // e.g. 192.168.0.1
	TargetSshKeyPath string `envconfig:"E2E_SSH_KEY_PATH" required:"true"` // e.g. /Users/username/key.pem
	TargetSshUser    string `envconfig:"E2E_SSH_USER" required:"true"`     // e.g. ubuntu
	TargetPort       string `envconfig:"E2E_SSH_PORT" required:"true"`
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
