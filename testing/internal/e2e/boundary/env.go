// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Address            string `envconfig:"BOUNDARY_ADDR" required:"true"`               // e.g. http://127.0.0.1:9200
	AuthMethodId       string `envconfig:"E2E_PASSWORD_AUTH_METHOD_ID" required:"true"` // e.g. ampw_1234567890
	AdminLoginName     string `envconfig:"E2E_PASSWORD_ADMIN_LOGIN_NAME" default:"admin"`
	AdminLoginPassword string `envconfig:"E2E_PASSWORD_ADMIN_PASSWORD" required:"true"`
}

func LoadConfig() (*Config, error) {
	var c Config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
