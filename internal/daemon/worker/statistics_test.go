// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func Test_sendStatistic(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                   string
		lastRoutingInfo        *LastRoutingInfo
		sessionSetup           func(sm *session.TestManager)
		expectedInternalErrMsg string
		expectedServerErrMsg   string
		expectedSessions       bool
	}{
		{
			name:                   "nil last status",
			expectedInternalErrMsg: "missing latest status",
		},
		{
			name: "empty worker id",
			lastRoutingInfo: &LastRoutingInfo{
				RoutingInfoResponse: &pbs.RoutingInfoResponse{},
			},
			expectedInternalErrMsg: "worker id is empty",
		},
		{
			name: "empty sessions",
			lastRoutingInfo: &LastRoutingInfo{
				RoutingInfoResponse: &pbs.RoutingInfoResponse{
					WorkerId: "w_1234567890",
				},
			},
		},
		{
			name: "server error",
			lastRoutingInfo: &LastRoutingInfo{
				RoutingInfoResponse: &pbs.RoutingInfoResponse{
					WorkerId: "w_1234567890",
				},
			},
			sessionSetup: func(sm *session.TestManager) {
				require.NotNil(t, sm)
				sm.StoreSession("s_1234567890")
				sm.StoreConnection(t, "s_1234567890", "c_1234567890")
			},
			expectedServerErrMsg: "testing connection timeout",
		},
		{
			name: "success",
			lastRoutingInfo: &LastRoutingInfo{
				RoutingInfoResponse: &pbs.RoutingInfoResponse{
					WorkerId: "w_1234567890",
				},
			},
			sessionSetup: func(sm *session.TestManager) {
				require.NotNil(t, sm)
				sm.StoreSession("s_1234567890")
				sm.StoreConnection(t, "s_1234567890", "c_1234567890")
			},
			expectedSessions: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)

			w := NewTestWorker(t, &TestWorkerOpts{
				DisableAutoStart: true,
				Name:             tt.name,
			})

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(err)
			cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(err)

			sm := session.NewTestManager(t, pbs.NewMockSessionServiceClient())
			if tt.sessionSetup != nil {
				tt.sessionSetup(sm)
			}
			w.Worker().sessionManager = sm

			serverInvoked := false
			fakeServer := &mockServerCoordinationService{
				nextStatisticAssert: func(req *pbs.StatisticsRequest) (*pbs.StatisticsResponse, error) {
					serverInvoked = true
					if tt.expectedInternalErrMsg != "" {
						assert.Fail("server should not send statistics information for internal errors")
					}
					if tt.expectedServerErrMsg != "" {
						return &pbs.StatisticsResponse{}, errors.New(tt.expectedServerErrMsg)
					}
					if !tt.expectedSessions {
						assert.Fail("server should not send statistics information when there are no managed sessions")
					}
					require.NotNil(req)
					assert.Equal("w_1234567890", req.WorkerId)
					require.Len(req.Sessions, 1)
					assert.Equal("s_1234567890", req.Sessions[0].SessionId)
					require.Len(req.Sessions[0].Connections, 1)
					assert.Equal("c_1234567890", req.Sessions[0].Connections[0].ConnectionId)
					return &pbs.StatisticsResponse{}, nil
				},
			}
			srv := grpc.NewServer()
			pbs.RegisterServerCoordinationServiceServer(srv, fakeServer)
			w.Worker().GrpcClientConn.Store(cc)
			w.Worker().lastRoutingInfoSuccess.Store(tt.lastRoutingInfo)

			serverStarted := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				close(serverStarted)
				assert.NoError(srv.Serve(ln))
			}()

			<-serverStarted
			actualErr := w.Worker().sendStatistic(context.Background())

			if tt.expectedInternalErrMsg != "" {
				require.Error(actualErr)
				assert.ErrorContains(actualErr, tt.expectedInternalErrMsg)
				assert.False(serverInvoked)
				return
			}
			if tt.expectedServerErrMsg != "" {
				require.Error(actualErr)
				assert.ErrorContains(actualErr, tt.expectedServerErrMsg)
				assert.True(serverInvoked)
				return
			}
			require.NoError(actualErr)
			require.Equal(tt.expectedSessions, serverInvoked)

			srv.GracefulStop()
			wg.Wait()
		})
	}
}
