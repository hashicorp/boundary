// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	// Reinitialize the roots at startup
	TestWorkerAuthCaReinitialize bool

	// This is derived from the config.Config. It tracks the state of the
	// rate limiter's configuration, and is updated if the config changes via a
	// SIGHUP.
	rateLimiterConfig *rateLimiterConfig
}
