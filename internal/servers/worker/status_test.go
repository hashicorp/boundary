package worker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestWorkerWaitForNextSuccessfulStatusUpdate(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	for _, name := range []string{"ok", "timeout"} {
		t.Run(name, func(t *testing.T) {
			// As-needed initialization of a mock worker
			w := &Worker{
				logger:            hclog.New(nil),
				lastStatusSuccess: new(atomic.Value),
				baseContext:       context.Background(),
				conf: &Config{
					Server: &base.Server{
						StatusGracePeriodDuration: time.Second * 1,
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
