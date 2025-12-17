// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-rate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger(t *testing.T, testLock hclog.Locker) hclog.Logger {
	t.Helper()
	return hclog.New(&hclog.LoggerOptions{
		Mutex:      testLock,
		Name:       "test",
		JSONFormat: true,
	})
}

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
			ratelimit.DefaultLimiterMaxQuotas(),
			false,
			&rateLimiterConfig{
				maxSize:  338169,
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
			ratelimit.DefaultLimiterMaxQuotas(),
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
					ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
					ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
					ApiRateLimitDisable:     true,
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
						ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
					ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
						ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
					ApiRateLimiterMaxQuotas: 3000,
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
						ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
					ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
						ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
					ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
						ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
					ApiRateLimiterMaxQuotas: 0,
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
						ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
					ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
						ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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
						ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
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

func Test_rateLimiterConfig_writeSysEvent(t *testing.T) {
	c := event.TestEventerConfig(t, t.Name())

	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)
	e, err := event.NewEventer(testLogger, testLock, t.Name(), c.EventerConfig)
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309", EventId: "411"}

	testCtx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	testCtx, err = event.NewRequestInfoContext(testCtx, info)
	require.NoError(t, err)

	cases := []struct {
		name         string
		setup        func(n string) error
		cleanup      func()
		sinkFileName string
		configs      ratelimit.Configs
		maxSize      int
		disabled     bool
	}{
		{
			name: "defaults",
			setup: func(n string) error {
				return event.InitSysEventer(testLogger, testLock, n, event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:      func() { event.TestResetSystEventer(t) },
			sinkFileName: c.AllEvents.Name(),
			configs:      nil,
			maxSize:      ratelimit.DefaultLimiterMaxQuotas(),
			disabled:     false,
		},
		{
			name: "override",
			setup: func(n string) error {
				return event.InitSysEventer(testLogger, testLock, n, event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:      func() { event.TestResetSystEventer(t) },
			sinkFileName: c.AllEvents.Name(),
			configs: ratelimit.Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       rate.LimitPerTotal.String(),
					Limit:     100,
					Period:    time.Minute,
					Unlimited: false,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       rate.LimitPerIPAddress.String(),
					Limit:     100,
					Period:    time.Minute,
					Unlimited: false,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       rate.LimitPerAuthToken.String(),
					Limit:     100,
					Period:    time.Minute,
					Unlimited: false,
				},
			},
			maxSize:  ratelimit.DefaultLimiterMaxQuotas(),
			disabled: false,
		},
		{
			name: "max_size",
			setup: func(n string) error {
				return event.InitSysEventer(testLogger, testLock, n, event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:      func() { event.TestResetSystEventer(t) },
			sinkFileName: c.AllEvents.Name(),
			configs:      nil,
			maxSize:      3000,
			disabled:     false,
		},
		{
			name: "disabled",
			setup: func(n string) error {
				return event.InitSysEventer(testLogger, testLock, n, event.WithEventerConfig(&c.EventerConfig))
			},
			cleanup:      func() { event.TestResetSystEventer(t) },
			sinkFileName: c.AllEvents.Name(),
			configs:      nil,
			maxSize:      0,
			disabled:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				require.NoError(t, tc.setup(t.Name()))
			}
			if tc.cleanup != nil {
				defer tc.cleanup()
			}

			wantFile, err := os.Open(filepath.Join("testdata", t.Name()+".json"))
			require.NoError(t, err)
			defer wantFile.Close()
			want := &cloudevents.Event{}
			wantDecoder := json.NewDecoder(wantFile)
			err = wantDecoder.Decode(want)
			require.NoError(t, err)

			rlc, err := newRateLimiterConfig(testCtx, tc.configs, tc.maxSize, tc.disabled)
			require.NoError(t, err)

			rlc.writeSysEvent(testCtx)

			defer func() { _ = os.WriteFile(tc.sinkFileName, nil, 0o666) }()
			b, err := os.ReadFile(tc.sinkFileName)
			require.NoError(t, err)

			got := &cloudevents.Event{}
			err = json.Unmarshal(b, got)
			require.NoErrorf(t, err, "json: %s", string(b))

			assert.Empty(t, cmp.Diff(
				got,
				want,
				cmpopts.IgnoreFields(cloudevents.Event{}, "ID", "Time", "Data"),
			))

			gotData := got.Data.(map[string]interface{})
			wantData := want.Data.(map[string]interface{})
			assert.Equal(t, len(gotData), len(wantData))

			for k, v := range wantData {
				switch k {
				case "data":
					wantDataData := v.(map[string]interface{})
					gotDataData := gotData[k].(map[string]interface{})
					assert.Equal(t, len(gotDataData), len(wantDataData))
					for k, v := range wantDataData {
						switch k {
						case "limits":
							wantResources := v.(map[string]interface{})
							gotResources := gotDataData[k].(map[string]interface{})
							for k, v := range wantResources {
								gotv, ok := gotResources[k]
								require.True(t, ok)

								wantResourceLimits := v.(map[string]interface{})
								gotResourceLimits := gotv.(map[string]interface{})
								require.Equal(t, len(wantResourceLimits), len(gotResourceLimits))

								for k, v := range wantResourceLimits {
									gotv, ok := gotResourceLimits[k]
									require.True(t, ok)
									gotActionLimits := v.([]interface{})
									wantActionLimits := gotv.([]interface{})
									require.Equal(t, len(gotActionLimits), len(wantActionLimits))

									assert.ElementsMatch(t, gotActionLimits, wantActionLimits)
								}
							}
						case "max_size", "msg", "disabled":
							assert.Equal(t, v, gotDataData[k])
						default:
							require.Fail(t, "unexpected key %s", k)
						}
					}
				case "op", "version":
					assert.Equal(t, v, gotData[k])
				default:
					require.Fail(t, "unexpected key %s", k)
				}
			}
		})
	}
}
