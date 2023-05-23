// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controller

import (
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
)

type Config struct {
	// The base Server object, containing things shared between Controllers and
	// Workers
	*base.Server
	// The underlying configuration, passed in here to avoid duplicating values
	// everywhere
	RawConfig *config.Config
	// If set, authorization checking occurrs but failures are ignored
	DisableAuthorizationFailures bool
	// Override worker auth CA certificate lifetime for testing
	TestOverrideWorkerAuthCaCertificateLifetime time.Duration
}
