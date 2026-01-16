// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/hashicorp/go-hclog"
)

type options struct {
	withRefreshInterval                    time.Duration
	withRecheckSupportInterval             time.Duration
	testWithIntervalRandomizationFactor    float64
	testWithIntervalRandomizationFactorSet bool
	WithReadyToServeNotificationCh         chan struct{}
	withBoundaryTokenReaderFunc            cache.BoundaryTokenReaderFn

	withUrl              string
	withLogger           hclog.Logger
	withHomeDir          string
	withForceResetSchema bool
}

// Option - how options are passed as args
type Option func(*options) error

func getDefaultOptions() options {
	return options{}
}

func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()

	for _, o := range opt {
		if err := o(&opts); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

// WithHomeDir provides an optional home directory to use.
func WithHomeDir(_ context.Context, dir string) Option {
	return func(o *options) error {
		o.withHomeDir = dir
		return nil
	}
}

// withRefreshInterval provides an optional refresh interval.
func withRefreshInterval(_ context.Context, d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return fmt.Errorf("provided refresh interval %q must be positive", d)
		}
		o.withRefreshInterval = d
		return nil
	}
}

// withRecheckSupportInterval provides an optional full fetch interval.
func withRecheckSupportInterval(_ context.Context, d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return fmt.Errorf("provided recheck support interval %q must be positive", d)
		}
		o.withRecheckSupportInterval = d
		return nil
	}
}

// testWithIntervalRandomizationFactor provides an optional test interval
// randomization factor.
func testWithIntervalRandomizationFactor(_ context.Context, f float64) Option {
	return func(o *options) error {
		if f < 0 {
			return fmt.Errorf("testWithIntervalRandomizationFactor must be non negative")
		}
		o.testWithIntervalRandomizationFactor = f
		o.testWithIntervalRandomizationFactorSet = true
		return nil
	}
}

// WithUrl provides optional url
func WithUrl(_ context.Context, url string) Option {
	return func(o *options) error {
		o.withUrl = url
		return nil
	}
}

// WithLogger provides an optional logger.
func WithLogger(_ context.Context, logger hclog.Logger) Option {
	return func(o *options) error {
		o.withLogger = logger
		return nil
	}
}

// WithBoundaryTokenReaderFunc provides an option for specifying a BoundaryTokenReaderFn
func WithBoundaryTokenReaderFunc(_ context.Context, fn cache.BoundaryTokenReaderFn) Option {
	return func(o *options) error {
		o.withBoundaryTokenReaderFunc = fn
		return nil
	}
}

// WithForceResetSchema provides an optional way to force resetting the schema,
// e.g. wiping the cache
func WithForceResetSchema(_ context.Context, force bool) Option {
	return func(o *options) error {
		o.withForceResetSchema = force
		return nil
	}
}

// WithReadyToServeNotificationCh provides an optional channel to notify when
// the server is ready to serve; mainly used for test timing but exported for
// availability. The channel will be closed just before the HTTP server is
// started.
func WithReadyToServeNotificationCh(_ context.Context, readyCh chan struct{}) Option {
	return func(o *options) error {
		o.WithReadyToServeNotificationCh = readyCh
		return nil
	}
}
