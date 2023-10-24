// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
)

type options struct {
	withDebug                          bool
	withRefreshInterval                time.Duration
	withFullFetchInterval              time.Duration
	withIntervalRandomizationFactor    float64
	withIntervalRandomizationFactorSet bool
	withBoundaryTokenReaderFunc        cache.BoundaryTokenReaderFn
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

// WithDebug provides an optional debug flag.
func WithDebug(_ context.Context, debug bool) Option {
	return func(o *options) error {
		o.withDebug = debug
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

// withFullFetchInterval provides an optional full fetch interval.
func withFullFetchInterval(_ context.Context, d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return fmt.Errorf("provided full fetch interval %q must be positive", d)
		}
		o.withFullFetchInterval = d
		return nil
	}
}

// withIntervalRandomizationFactor provides an optional interval randomziation factor.
func withIntervalRandomizationFactor(_ context.Context, f float64) Option {
	return func(o *options) error {
		if f < 0 {
			return fmt.Errorf("withIntervalRandomizationFactor must be non negative")
		}
		o.withIntervalRandomizationFactor = f
		o.withIntervalRandomizationFactorSet = true
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
