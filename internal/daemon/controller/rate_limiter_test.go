// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/go-rate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newRateLimiterConfig(t *testing.T) {
	ctx := context.Background()

	var configs ratelimit.Configs
	defaultLimits, err := configs.Limits(ctx)
	require.NoError(t, err)

	cases := []struct {
		name     string
		configs  ratelimit.Configs
		maxSize  int
		disabled bool
		want     *rateLimiterConfig
		wantErr  error
	}{
		{
			"disabled",
			nil,
			0,
			true,
			&rateLimiterConfig{disabled: true},
			nil,
		},
		{
			"defaults",
			nil,
			ratelimit.DefaultLimiterMaxEntries(),
			false,
			&rateLimiterConfig{
				maxSize:  296148,
				configs:  nil,
				disabled: false,
				limits:   defaultLimits,
			},
			nil,
		},
		{
			"disabledWithConfigs",
			ratelimit.Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     100,
					Period:    time.Minute,
					Unlimited: false,
				},
			},
			ratelimit.DefaultLimiterMaxEntries(),
			true,
			nil,
			fmt.Errorf("controller.newRateLimiterConfig: disabled rate limiter with rate limit configs: configuration issue: error #5000"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newRateLimiterConfig(ctx, tc.configs, tc.maxSize, tc.disabled)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(
				tc.want,
				got,
				cmp.AllowUnexported(rateLimiterConfig{}),
				cmpopts.IgnoreFields(rateLimiterConfig{}, "limits"),
			))
			assert.ElementsMatch(t, got.limits, tc.want.limits)
		})
	}
}

func TestController_initializeRateLimiter(t *testing.T) {
	// Disabling eventing so reduce noise.
	event.TestWithoutEventing(t)

	cases := []struct {
		name           string
		conf           *config.Config
		wantNopLimiter bool
		wantErr        error
	}{
		{
			"disabled",
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimitDisable: true,
				},
			},
			true,
			nil,
		},
		{
			"defaults",
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
				},
			},
			false,
			nil,
		},
		{
			"invalid",
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimits: ratelimit.Configs{
						{
							Resources: []string{"*"},
							Actions:   []string{"*"},
							Per:       "total",
							Limit:     100,
							Period:    time.Minute,
							Unlimited: false,
						},
					},
					ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					ApiRateLimitDisable:      true,
				},
			},
			false,
			fmt.Errorf("controller.newRateLimiterConfig: disabled rate limiter with rate limit configs: configuration issue: error #5000"),
		},
		{
			"nilConfig",
			nil,
			false,
			fmt.Errorf("controller.(Controller).initializeRateLimiter: nil config: parameter violation: error #100"),
		},
		{
			"nilConfigController",
			&config.Config{
				Controller: nil,
			},
			false,
			fmt.Errorf("controller.(Controller).initializeRateLimiter: nil config.Controller: parameter violation: error #100"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Controller{
				baseContext: context.Background(),
				conf: &Config{
					RawConfig: tc.conf,
				},
			}
			err := c.initializeRateLimiter(tc.conf)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)

			if tc.wantNopLimiter {
				assert.Equal(t, rate.NopLimiter, c.rateLimiter)
				return
			}

			_, ok := c.rateLimiter.(*rate.Limiter)
			assert.True(t, ok, "expected rate.Limiter")
			assert.NotNil(t, c.rateLimiter)
		})
	}
}

func TestControllerReloadRateLimiter(t *testing.T) {
	// Disabling eventing so reduce noise.
	event.TestWithoutEventing(t)

	cases := []struct {
		name           string
		c              *Controller
		conf           *config.Config
		wantNewLimiter bool
		wantErr        error
	}{
		{
			"newConfigs",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimits: ratelimit.Configs{
						{
							Resources: []string{"*"},
							Actions:   []string{"*"},
							Per:       "total",
							Limit:     100,
							Period:    time.Minute,
							Unlimited: false,
						},
					},
					ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
				},
			},
			true,
			nil,
		},
		{
			"newMaxSize",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimiterMaxEntries: 3000,
				},
			},
			true,
			nil,
		},
		{
			"newDisabled",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimitDisable: true,
				},
			},
			true,
			nil,
		},
		{
			"newEnabled",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimitDisable: true,
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
				},
			},
			true,
			nil,
		},
		{
			"newInvalid",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					ApiRateLimits: ratelimit.Configs{
						{
							Resources: []string{"*"},
							Actions:   []string{"*"},
							Per:       "total",
							Limit:     100,
							Period:    time.Minute,
							Unlimited: false,
						},
					},
					ApiRateLimitDisable: true,
				},
			},
			false,
			fmt.Errorf("controller.newRateLimiterConfig: disabled rate limiter with rate limit configs: configuration issue: error #5000"),
		},
		{
			"newInvalidMaxSize",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimiterMaxEntries: 0,
					ApiRateLimits: ratelimit.Configs{
						{
							Resources: []string{"*"},
							Actions:   []string{"*"},
							Per:       "total",
							Limit:     100,
							Period:    time.Minute,
							Unlimited: false,
						},
					},
				},
			},
			false,
			fmt.Errorf("controller.(Controller).ReloadRateLimiter: unknown, unknown: error #0: rate.NewLimiter: rate.newExpirableStore: max size must be greater than zero: invalid max size"),
		},
		{
			"newConfigsNoChange",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			&config.Config{
				Controller: &config.Controller{
					ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
				},
			},
			false,
			nil,
		},
		{
			"nilNewConfigController",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			&config.Config{
				Controller: nil,
			},
			false,
			fmt.Errorf("controller.(Controller).ReloadRateLimiter: nil config.Controller: parameter violation: error #100"),
		},
		{
			"nilNewConfig",
			func() *Controller {
				conf := &config.Config{
					Controller: &config.Controller{
						ApiRateLimiterMaxEntries: ratelimit.DefaultLimiterMaxEntries(),
					},
				}
				c := &Controller{
					baseContext: context.Background(),
					conf: &Config{
						RawConfig: conf,
					},
				}
				err := c.initializeRateLimiter(conf)
				require.NoError(t, err)
				return c
			}(),
			nil,
			false,
			fmt.Errorf("controller.(Controller).ReloadRateLimiter: nil config: parameter violation: error #100"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prevLimiter := tc.c.getRateLimiter()
			err := tc.c.ReloadRateLimiter(tc.conf)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
			} else {
				require.NoError(t, err)
			}
			if tc.wantNewLimiter {
				assert.NotSame(t, prevLimiter, tc.c.getRateLimiter())
				return
			}
			assert.Same(t, prevLimiter, tc.c.getRateLimiter())
		})
	}
}
