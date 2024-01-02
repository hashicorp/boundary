// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package worker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestWorkerWaitForNextSuccessfulStatusUpdate(t *testing.T) {
	testConfig := event.DefaultEventerConfig()
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
	})
	err := event.InitSysEventer(testLogger, testLock, "TestWorkerWaitForNextSuccessfulStatusUpdate", event.WithEventerConfig(testConfig))
	require.NoError(t, err)
	for _, name := range []string{"ok", "timeout"} {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)

			// As-needed initialization of a mock worker
			w := &Worker{
				logger:                      hclog.New(nil),
				lastStatusSuccess:           new(atomic.Value),
				baseContext:                 context.Background(),
				successfulStatusGracePeriod: new(atomic.Int64),
				conf: &Config{
					Server: &base.Server{},
				},
			}

			// This is present in New()
			w.lastStatusSuccess.Store((*LastStatusInformation)(nil))
			w.successfulStatusGracePeriod.Store(int64(time.Second * 2))

			var wg sync.WaitGroup
			var err error
			wg.Add(1)
			go func() {
				err = w.WaitForNextSuccessfulStatusUpdate()
				wg.Done()
			}()

			if name == "ok" {
				time.Sleep(time.Millisecond * 100)
				w.lastStatusSuccess.Store(&LastStatusInformation{StatusTime: time.Now()})
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
