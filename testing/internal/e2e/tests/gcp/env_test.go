// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package gcp_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	GcpPrivateKeyId   string `envconfig:"E2E_GCP_PRIVATE_KEY_ID" required:"true"`
	GcpPrivateKey     string `envconfig:"E2E_GCP_PRIVATE_KEY" required:"true"`
	GcpZone           string `envconfig:"E2E_GCP_ZONE" required:"true"`       // e.g. "us-central1-a"
	GcpProjectId      string `envconfig:"E2E_GCP_PROJECT_ID" required:"true"` // e.g. "my-project"
	GcpClientEmail    string `envconfig:"E2E_GCP_CLIENT_EMAIL" required:"true"`
	GcpHostSetFilter1 string `envconfig:"E2E_GCP_HOST_SET_FILTER1" required:"true"`
	GcpHostSetFilter2 string `envconfig:"E2E_GCP_HOST_SET_FILTER2" required:"true"`
	GcpHostSetIps     string `envconfig:"E2E_GCP_HOST_SET_IPS" required:"true"`
	GcpTargetSshKey   string `envconfig:"E2E_GCP_TARGET_SSH_KEY" required:"true"`
	GcpTargetAddress  string `envconfig:"E2E_TARGET_ADDRESS" required:"true"` // e.g. "192.168.0.1"
	GcpTargetSshUser  string `envconfig:"E2E_SSH_USER" required:"true"`       // e.g. "ubuntu"
	GcpTargetPort     string `envconfig:"E2E_TARGET_PORT" required:"true"`    // e.g. "22"
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
