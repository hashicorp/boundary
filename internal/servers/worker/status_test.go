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
	// do not run using t.Parallel() since it relies on the sys eventer
	event.TestEnableEventing(t, true)
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
				logger:            hclog.New(nil),
				lastStatusSuccess: new(atomic.Value),
				baseContext:       context.Background(),
				conf: &Config{
					Server: &base.Server{
						StatusGracePeriodDuration: time.Second * 2,
					},
				},
			}

			// This is present in New()
			w.lastStatusSuccess.Store((*LastStatusInformation)(nil))

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
