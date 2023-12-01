// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/go-rate"
)

type rateLimiterConfig struct {
	maxSize  int
	disabled bool
	configs  ratelimit.Configs

	limits []rate.Limit
}

func newRateLimiterConfig(ctx context.Context, configs ratelimit.Configs, maxSize int, disabled bool) (*rateLimiterConfig, error) {
	const op = "controller.newRateLimiterConfig"

	switch {
	case disabled && len(configs) != 0:
		return nil, errors.New(ctx, errors.InvalidConfiguration, op, "disabled rate limiter with rate limit configs")
	}

	var limits []rate.Limit
	var err error
	if !disabled {
		if limits, err = configs.Limits(ctx); err != nil {
			return nil, err
		}
	}

	return &rateLimiterConfig{
		maxSize:  maxSize,
		disabled: disabled,
		configs:  configs,
		limits:   limits,
	}, nil
}

func (c *Controller) initializeRateLimiter(conf *config.Config) error {
	const op = "controller.(Controller).initializeRateLimiter"
	switch {
	case conf == nil:
		return errors.New(c.baseContext, errors.InvalidParameter, op, "nil config")
	case conf.Controller == nil:
		return errors.New(c.baseContext, errors.InvalidParameter, op, "nil config.Controller")
	}

	c.rateLimiterMu.Lock()
	defer c.rateLimiterMu.Unlock()

	rlConfig, err := newRateLimiterConfig(
		c.baseContext,
		conf.Controller.ApiRateLimits,
		conf.Controller.ApiRateLimiterMaxEntries,
		conf.Controller.ApiRateLimitDisable,
	)
	if err != nil {
		return err
	}

	switch {
	case rlConfig.disabled:
		c.rateLimiter = rate.NopLimiter
	default:
		c.rateLimiter, err = ratelimit.NewLimiter(rlConfig.limits, rlConfig.maxSize)
		if err != nil {
			return err
		}
	}

	c.conf.rateLimiterConfig = rlConfig

	return nil
}

func (c *Controller) getRateLimiter() ratelimit.Limiter {
	c.rateLimiterMu.RLock()
	defer c.rateLimiterMu.RUnlock()
	return c.rateLimiter
}

// ReloadRateLimiter replaces the Controller's rate.Limiter with a new rate.Limiter
// using the supplied ratelimit.Configs and max entries. If the configs and max
// entries match the current values, the rate.Limiter is not replaced and no
// error is returned. Otherwise the rate.Limiter is replaced, and the old rate.Limiter
// is shutdown. This means that a client's quota is effectively reset if the
// configuration changes.
func (c *Controller) ReloadRateLimiter(newConfig *config.Config) error {
	const op = "controller.(Controller).ReloadRateLimiter"

	switch {
	case newConfig == nil:
		return errors.New(c.baseContext, errors.InvalidParameter, op, "nil config")
	case newConfig.Controller == nil:
		return errors.New(c.baseContext, errors.InvalidParameter, op, "nil config.Controller")
	}

	rlConfig, err := newRateLimiterConfig(
		c.baseContext,
		newConfig.Controller.ApiRateLimits,
		newConfig.Controller.ApiRateLimiterMaxEntries,
		newConfig.Controller.ApiRateLimitDisable,
	)
	if err != nil {
		return err
	}

	// Config has not changed, no need to reload.
	if c.conf.rateLimiterConfig.maxSize == rlConfig.maxSize &&
		c.conf.rateLimiterConfig.disabled == rlConfig.disabled &&
		c.conf.rateLimiterConfig.configs.Equal(rlConfig.configs) {
		return nil
	}

	var limiter ratelimit.Limiter
	switch {
	case rlConfig.disabled:
		limiter = rate.NopLimiter
	default:
		limiter, err = ratelimit.NewLimiter(rlConfig.limits, rlConfig.maxSize)
		if err != nil {
			return errors.Wrap(c.baseContext, err, op)
		}

	}
	c.rateLimiterMu.Lock()
	old := c.rateLimiter
	c.rateLimiter = limiter
	c.conf.rateLimiterConfig = rlConfig
	c.rateLimiterMu.Unlock()

	return old.Shutdown()
}
