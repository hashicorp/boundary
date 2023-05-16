// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package database_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetSshUser      string `envconfig:"E2E_SSH_USER" required:"true"`     // e.g. ubuntu
	TargetSshKeyPath   string `envconfig:"E2E_SSH_KEY_PATH" required:"true"` // e.g. /Users/username/key.pem
	TargetPort         string `envconfig:"E2E_SSH_PORT" default:"22"`
	VaultSecretPath    string `envconfig:"E2E_VAULT_SECRET_PATH" default:"e2e_secrets"`
	AwsAccessKeyId     string `envconfig:"E2E_AWS_ACCESS_KEY_ID" required:"true"`
	AwsSecretAccessKey string `envconfig:"E2E_AWS_SECRET_ACCESS_KEY" required:"true"`
	AwsHostSetFilter   string `envconfig:"E2E_AWS_HOST_SET_FILTER" required:"true"` // e.g. "tag:testtag=true"
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
