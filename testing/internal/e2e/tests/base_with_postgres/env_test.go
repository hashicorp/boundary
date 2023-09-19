// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_with_postgres_test

import "github.com/kelseyhightower/envconfig"

type config struct {
	TargetAddress    string `envconfig:"E2E_TARGET_ADDRESS" required:"true"` // e.g. 192.168.0.1
	TargetPort       string `envconfig:"E2E_TARGET_PORT" required:"true"`
	PostgresDbName   string `envconfig:"E2E_POSTGRES_DB_NAME" required:"true"`
	PostgresUser     string `envconfig:"E2E_POSTGRES_USER" required:"true"`
	PostgresPassword string `envconfig:"E2E_POSTGRES_PASSWORD" required:"true"`
}

func loadTestConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
