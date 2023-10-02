// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"time"
)

const (
	// DefaultLimiterMaxEntries is the default maximum number of quotas that
	// can be tracked by the rate limiter.
	DefaultLimiterMaxEntries = 16384 // TODO: pick a meaningful default value
)

// Config is used to configure rate limits. Each config is used to specify
// the maximum number of requests that can be made in a time period for the
// corresponding resources and actions.
type Config struct {
	Resources []string      `hcl:"resources"`
	Actions   []string      `hcl:"actions"`
	Per       string        `hcl:"per"`
	Limit     int           `hcl:"limit"`
	PeriodHCL string        `hcl:"period"`
	Period    time.Duration `hcl:"-"`
	Unlimited bool          `hcl:"unlimited"`
}

// Configs is an ordered set of Config.
type Configs []*Config
