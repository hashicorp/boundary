// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/event"
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

func TestWriteSysEvent(t *testing.T) {
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
		limits       []*rate.Limit
		maxEntries   int
	}{
		{
			"defaults",
			func(n string) error {
				return event.InitSysEventer(testLogger, testLock, n, event.WithEventerConfig(&c.EventerConfig))
			},
			func() { event.TestResetSystEventer(t) },
			c.AllEvents.Name(),
			func() []*rate.Limit {
				var c Configs
				l, err := c.Limits(testCtx)
				require.NoError(t, err)
				return l
			}(),
			DefaultLimiterMaxEntries(),
		},
		{
			"override",
			func(n string) error {
				return event.InitSysEventer(testLogger, testLock, n, event.WithEventerConfig(&c.EventerConfig))
			},
			func() { event.TestResetSystEventer(t) },
			c.AllEvents.Name(),
			func() []*rate.Limit {
				c := Configs{
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
				}
				l, err := c.Limits(testCtx)
				require.NoError(t, err)
				return l
			}(),
			DefaultLimiterMaxEntries(),
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

			err = WriteLimitsSysEvent(testCtx, tc.limits, tc.maxEntries)
			require.NoError(t, err)

			defer func() { _ = os.WriteFile(tc.sinkFileName, nil, 0o666) }()
			b, err := ioutil.ReadFile(tc.sinkFileName)
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
								require.Equal(t, len(gotResourceLimits), len(wantResourceLimits))

								for k, v := range wantResourceLimits {
									gotv, ok := gotResourceLimits[k]
									require.True(t, ok)
									gotActionLimits := v.([]interface{})
									wantActionLimits := gotv.([]interface{})
									require.Equal(t, len(gotActionLimits), len(wantActionLimits))

									assert.ElementsMatch(t, gotActionLimits, wantActionLimits)
								}
							}
						case "max_entries", "msg":
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
