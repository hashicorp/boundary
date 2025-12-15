// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package infra

import "github.com/kelseyhightower/envconfig"

type Config struct {
	DockerMirror    string `envconfig:"DOCKER_MIRROR" default:"docker.mirror.hashicorp.services"`
	BoundaryLicense string `envconfig:"BOUNDARY_LICENSE" default:""`
}

func LoadConfig() (*Config, error) {
	var c Config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
