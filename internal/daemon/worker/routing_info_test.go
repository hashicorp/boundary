// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestWorkerWaitForNextSuccessfulRoutingInfoUpdate(t *testing.T) {
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestWorkerWaitForNextSuccessfulRoutingInfoUpdate", event.WithEventerConfig(testConfig))
	require.NoError(t, err)
	t.Cleanup(func() { event.TestResetSystEventer(t) })
	for _, name := range []string{"ok", "timeout"} {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)

			// As-needed initialization of a mock worker
			w := &Worker{
				logger:                           hclog.New(nil),
				lastRoutingInfoSuccess:           new(atomic.Value),
				baseContext:                      context.Background(),
				successfulRoutingInfoGracePeriod: new(atomic.Int64),
				conf: &Config{
					Server: &base.Server{},
				},
			}

			// This is present in New()
			w.lastRoutingInfoSuccess.Store((*LastRoutingInfo)(nil))
			w.successfulRoutingInfoGracePeriod.Store(int64(common.DefaultRoutingInfoTimeout))

			var wg sync.WaitGroup
			var err error
			wg.Add(1)
			go func() {
				err = w.WaitForNextSuccessfulRoutingInfoUpdate()
				wg.Done()
			}()

			if name == "ok" {
				time.Sleep(time.Millisecond * 100)
				w.lastRoutingInfoSuccess.Store(&LastRoutingInfo{RoutingInfoTime: time.Now()})
			}

			wg.Wait()
			if name == "timeout" {
				require.ErrorIs(err, context.DeadlineExceeded)
			} else {
				require.NoError(err)
			}
		})
	}
}
