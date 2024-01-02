// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package common

import (
	"time"

	"github.com/hashicorp/boundary/internal/server"
)

// In the future we could make this configurable
const (
	// StatusInterval is the base duration used in the calculation of the random backoff
	// during the worker status report
	StatusInterval = 2 * time.Second

	// DefaultStatusTimeout is the timeout duration on status calls to the controller from
	// the worker
	DefaultStatusTimeout = server.DefaultLiveness / 3
)
