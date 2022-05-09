package worker

import (
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/require"
)

func TestTestWorkerLookupSession(t *testing.T) {
	require := require.New(t)
	// This loads the golang reference time, see those docs for more details. We
	// just use this as a stable non-zero time.
	refTime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")
	require.NoError(err)

	tw := new(TestWorker)
	tw.w = &Worker{
		sessionInfoMap: new(sync.Map),
	}
	tw.w.sessionInfoMap.Store("foo", &session.Info{
		Id:     "foo",
		Status: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
		ConnInfoMap: map[string]*session.ConnInfo{
			"one": {
				Id:        "one",
				Status:    pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
				CloseTime: refTime,
			},
		},
	})

	expected := TestSessionInfo{
		Id:     "foo",
		Status: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
		Connections: map[string]TestConnectionInfo{
			"one": {
				Id:        "one",
				Status:    pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
				CloseTime: refTime,
			},
		},
	}

	actual, ok := tw.LookupSession("foo")
	require.True(ok)
	require.Equal(expected, actual)
}

func TestTestWorkerLookupSessionMissing(t *testing.T) {
	require := require.New(t)
	tw := new(TestWorker)
	tw.w = &Worker{
		sessionInfoMap: new(sync.Map),
	}
	actual, ok := tw.LookupSession("missing")
	require.False(ok)
	require.Equal(TestSessionInfo{}, actual)
}
