// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package aws_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	AwsAccessKeyId     string `envconfig:"E2E_AWS_ACCESS_KEY_ID" required:"true"`
	AwsSecretAccessKey string `envconfig:"E2E_AWS_SECRET_ACCESS_KEY" required:"true"`
	AwsHostSetFilter1  string `envconfig:"E2E_AWS_HOST_SET_FILTER" required:"true"`  // e.g. "tag:testtag=true"
	AwsHostSetIps1     string `envconfig:"E2E_AWS_HOST_SET_IPS" required:"true"`     // e.g. "[\"1.2.3.4\", \"2.3.4.5\"]"
	AwsHostSetFilter2  string `envconfig:"E2E_AWS_HOST_SET_FILTER2" required:"true"` // e.g. "tag:testtagtwo=test"
	AwsHostSetIps2     string `envconfig:"E2E_AWS_HOST_SET_IPS2" required:"true"`    // e.g. "[\"1.2.3.4\"]"
	TargetSshKeyPath   string `envconfig:"E2E_SSH_KEY_PATH" required:"true"`         // e.g. "/Users/username/key.pem"
	TargetSshUser      string `envconfig:"E2E_SSH_USER" required:"true"`             // e.g. "ubuntu"
	TargetPort         string `envconfig:"E2E_SSH_PORT" default:"22"`
}

func loadConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
