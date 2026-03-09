// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package aws_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	AwsAccessKeyId      string `envconfig:"E2E_AWS_ACCESS_KEY_ID" required:"true"`
	AwsBucketName       string `envconfig:"E2E_AWS_BUCKET_NAME" required:"true"`
	AwsSecretAccessKey  string `envconfig:"E2E_AWS_SECRET_ACCESS_KEY" required:"true"`
	AwsHostSetFilter1   string `envconfig:"E2E_AWS_HOST_SET_FILTER" required:"true"`   // e.g. "tag:testtag=true"
	AwsHostSetIps1      string `envconfig:"E2E_AWS_HOST_SET_IPS" required:"true"`      // e.g. "[\"1.2.3.4\", \"2.3.4.5\"]"
	AwsHostSetFilter2   string `envconfig:"E2E_AWS_HOST_SET_FILTER2" required:"true"`  // e.g. "tag:testtagtwo=test"
	AwsHostSetIps2      string `envconfig:"E2E_AWS_HOST_SET_IPS2" required:"true"`     // e.g. "[\"1.2.3.4\"]"
	AwsRegion           string `envconfig:"E2E_AWS_REGION" required:"true"`            // e.g. "us-east-1"
	TargetSshKeyPath    string `envconfig:"E2E_SSH_KEY_PATH" required:"true"`          // e.g. "/Users/username/key.pem"
	TargetSshUser       string `envconfig:"E2E_SSH_USER" required:"true"`              // e.g. "ubuntu"
	TargetPort          string `envconfig:"E2E_TARGET_PORT" required:"true"`           // e.g. "22"
	TargetAddress       string `envconfig:"E2E_TARGET_ADDRESS" required:"true"`        // e.g. "192.168.0.1"
	WorkerTagIsolated   string `envconfig:"E2E_WORKER_TAG_ISOLATED" required:"true"`   // e.g. "isolated"
	WorkerTagCollocated string `envconfig:"E2E_WORKER_TAG_COLLOCATED" required:"true"` // e.g. "collocated"
	WorkerAddress       string `envconfig:"E2E_WORKER_ADDRESS" required:"true"`        // e.g. "192.168.0.2"
	MaxPageSize         int    `envconfig:"E2E_MAX_PAGE_SIZE" default:"1000"`
	IpVersion           string `envconfig:"E2E_IP_VERSION" default:"4"` // should always be 4, 6, or dual
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
