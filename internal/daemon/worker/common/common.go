// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"time"

	"github.com/hashicorp/boundary/internal/server"
)

// In the future we could make this configurable
const (
	// SessionInfoInterval is the base duration used in the calculation of the random backoff
	// during the worker session information report
	SessionInfoInterval = 2 * time.Second

	// RoutingInfoInterval is the interval at which the worker will send routing information
	// to the controller
	RoutingInfoInterval = 10 * time.Second

	// StatisticsInterval is the base duration used in the calculation of the random backoff
	// during the worker statistics report
	StatisticsInterval = 15 * time.Second

	// DefaultSessionInfoTimeout is the timeout duration on SessionInfo calls to the controller from
	// the worker
	DefaultSessionInfoTimeout = server.DefaultLiveness / 3

	// DefaultRoutingInfoTimeout is the timeout duration on routing info calls to the controller from
	// the worker
	DefaultRoutingInfoTimeout = server.DefaultLiveness / 2

	// DefaultStatisticsTimeout is the timeout duration on Statistics calls to the controller from
	// the worker
	DefaultStatisticsTimeout = server.DefaultLiveness
)
