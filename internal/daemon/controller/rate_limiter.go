// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/go-rate"
)

// limit is a representation of a rate.Limit that is used when emitting a sys
// event to report the rate limit configuration.
type limit struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Per       string `json:"per"`
	Unlimited bool   `json:"unlimited"`
	Limit     uint64 `json:"limit"`
	Period    string `json:"period"`
}

// Types used for the nested structure of the sys event.
type (
	actionLimits    []limit
	resourceActions map[string]actionLimits
	resources       map[string]resourceActions
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

// writeSysEvent writes a sys event for c
func (c *rateLimiterConfig) writeSysEvent(ctx context.Context) {
	const op = "controller.(rateLimiterConfig).writeSysEvent"

	if c.disabled {
		event.WriteSysEvent(
			ctx,
			op,
			"controller api rate limiter",
			"disabled",
			true,
		)
		return
	}

	e := make(resources)

	for _, l := range c.limits {
		var r resourceActions
		var a actionLimits
		var ok bool
		r, ok = e[l.GetResource()]
		if !ok {
			r = make(resourceActions)
			e[l.GetResource()] = r
		}

		a, ok = r[l.GetAction()]
		if !ok {
			a = make(actionLimits, 0, 3)
		}

		switch ll := l.(type) {
		case *rate.Limited:
			a = append(a, limit{
				Resource:  ll.Resource,
				Action:    ll.Action,
				Per:       ll.Per.String(),
				Unlimited: false,
				Limit:     ll.MaxRequests,
				Period:    ll.Period.String(),
			})
		case *rate.Unlimited:
			a = append(a, limit{
				Resource:  ll.Resource,
				Action:    ll.Action,
				Per:       ll.Per.String(),
				Unlimited: true,
			})
		}
		r[l.GetAction()] = a
	}
	event.WriteSysEvent(
		ctx,
		op,
		"controller api rate limiter",
		"limits",
		e,
		"max_size",
		c.maxSize,
	)
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
		conf.Controller.ApiRateLimiterMaxQuotas,
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

	rlConfig.writeSysEvent(c.baseContext)
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
		newConfig.Controller.ApiRateLimiterMaxQuotas,
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
	rlConfig.writeSysEvent(c.baseContext)

	return old.Shutdown()
}
