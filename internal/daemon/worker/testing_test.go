package worker

import (
	"context"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"testing"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

func TestTestWorkerLookupSession(t *testing.T) {
	require := require.New(t)

	tc := controller.NewTestController(t, nil)
	testWorker := server.TestKmsWorker(t, tc.DbConn(), tc.Config().WorkerAuthKms)
	ctx := tc.Context()
	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	tarClient := targets.NewClient(client)
	resp, err := tarClient.List(ctx, "global", targets.WithRecursive(true))
	require.NoError(err)
	require.NotEmpty(resp.Items)
	sessResp, err := tarClient.AuthorizeSession(context.Background(), resp.Items[0].Id)
	require.NoError(err)
	require.NotEmpty(sessResp.Item)
	sessionId := sessResp.Item.SessionId

	tw := NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams: tc.ClusterAddrs(),
		WorkerAuthKms:    tc.Config().WorkerAuthKms,
	})

	s, err := tw.w.sessionCache.RefreshSession(ctx, sessionId, testWorker.GetPublicId())
	require.NoError(err)
	require.NoError(s.Activate(ctx, sessResp.Item.AuthorizationToken))

	connCtx, connCancelFn := context.WithCancel(context.Background())
	ci, _, err := s.AuthorizeConnection(ctx, testWorker.GetPublicId(), connCtx, connCancelFn)
	require.NoError(err)

	expected := TestSessionInfo{
		Id:     sessionId,
		Status: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
		Connections: map[string]TestConnectionInfo{
			ci.Id: {
				Id:        ci.Id,
				Status:    ci.Status,
				CloseTime: ci.CloseTime,
			},
		},
	}

	actual, ok := tw.LookupSession(sessionId)
	require.True(ok)
	require.Equal(expected, actual)
}

func TestTestWorkerLookupSessionMissing(t *testing.T) {
	require := require.New(t)
	tw := NewTestWorker(t, nil)
	actual, ok := tw.LookupSession("missing")
	require.False(ok)
	require.Equal(TestSessionInfo{}, actual)
}

func TestTestWorker_WorkerAuthStorageKms(t *testing.T) {
	tests := []struct {
		name    string
		wrapper wrapping.Wrapper
	}{
		{
			name:    "Nil Wrapper",
			wrapper: nil,
		},
		{
			name:    "Valid Wrapper",
			wrapper: db.TestWrapper(t),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			tw := NewTestWorker(t, &TestWorkerOpts{
				WorkerAuthStorageKms: tt.wrapper,
			})
			require.Equal(tt.wrapper, tw.Config().WorkerAuthStorageKms)
		})
	}
}
