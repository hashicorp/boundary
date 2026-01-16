// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func Test_sendSessionInfo(t *testing.T) {
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
			name:                   "nil last routing info",
			expectedInternalErrMsg: "missing latest routing info",
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
			// Ensure the recorder manager is not used
			w.Worker().recorderManager = nil

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(err)
			cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(err)

			mockSessionClient := pbs.NewMockSessionServiceClient()
			mockSessionClient.CloseConnectionFn = func(ctx context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
				return &pbs.CloseConnectionResponse{}, nil
			}
			sm := session.NewTestManager(t, mockSessionClient)
			if tt.sessionSetup != nil {
				tt.sessionSetup(sm)
			}
			w.Worker().sessionManager = sm

			serverInvoked := false
			fakeServer := &mockServerCoordinationService{
				nextSessionInfoAssert: func(req *pbs.SessionInfoRequest) (*pbs.SessionInfoResponse, error) {
					serverInvoked = true
					if tt.expectedInternalErrMsg != "" {
						assert.Fail("server should not send session information for internal errors")
					}
					if tt.expectedServerErrMsg != "" {
						return &pbs.SessionInfoResponse{}, errors.New(tt.expectedServerErrMsg)
					}
					if !tt.expectedSessions {
						assert.Fail("server should not send session information when there are no managed sessions")
					}
					require.NotNil(req)

					assert.Equal("w_1234567890", req.WorkerId)
					require.Len(req.Sessions, 1)
					assert.Equal("s_1234567890", req.Sessions[0].SessionId)

					return &pbs.SessionInfoResponse{}, nil
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
			actualErr := w.Worker().sendSessionInfo(context.Background())

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

	t.Run("close non active managed sessions connections and ignore non existing sessions", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)

		w := NewTestWorker(t, &TestWorkerOpts{
			DisableAutoStart: true,
			Name:             "close non active sessions and connections",
		})
		// Ensure the recorder manager is not used
		w.Worker().recorderManager = nil

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(err)
		cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(err)

		mockSessionClient := pbs.NewMockSessionServiceClient()
		mockSessionClient.CloseConnectionFn = func(ctx context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
			return &pbs.CloseConnectionResponse{}, nil
		}
		sm := session.NewTestManager(t, mockSessionClient)
		sm.StoreSession("s_1234567890")
		sm.StoreConnection(t, "s_1234567890", "c_1234567890")
		w.Worker().sessionManager = sm

		serverInvoked := false
		fakeServer := &mockServerCoordinationService{
			nextSessionInfoAssert: func(req *pbs.SessionInfoRequest) (*pbs.SessionInfoResponse, error) {
				serverInvoked = true
				assert.Equal("w_1234567890", req.WorkerId)
				require.Len(req.Sessions, 1)
				assert.Equal("s_1234567890", req.Sessions[0].SessionId)
				return &pbs.SessionInfoResponse{
					NonActiveSessions: []*pbs.Session{
						{
							SessionId:     "s_1234567890",
							SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
							SessionType:   pbs.SessionType_SESSION_TYPE_INGRESSED,
							Connections: []*pbs.Connection{
								{
									ConnectionId: "c_1234567890",
									Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
								},
							},
						},
						{
							SessionId:     "s_dne",
							SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
							SessionType:   pbs.SessionType_SESSION_TYPE_INGRESSED,
							Connections: []*pbs.Connection{
								{
									ConnectionId: "c_dne",
									Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
								},
							},
						},
					},
				}, nil
			},
		}

		srv := grpc.NewServer()
		pbs.RegisterServerCoordinationServiceServer(srv, fakeServer)
		w.Worker().GrpcClientConn.Store(cc)
		w.Worker().lastRoutingInfoSuccess.Store(&LastRoutingInfo{
			RoutingInfoResponse: &pbs.RoutingInfoResponse{
				WorkerId: "w_1234567890",
			},
		})

		serverStarted := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			close(serverStarted)
			assert.NoError(srv.Serve(ln))
		}()

		<-serverStarted
		actualErr := w.Worker().sendSessionInfo(context.Background())

		require.NoError(actualErr)
		assert.True(serverInvoked)
		closedSession := w.Worker().sessionManager.Get("s_1234567890")
		assert.Nil(closedSession)

		srv.GracefulStop()
		wg.Wait()
	})

	t.Run("validate closing local connections after last successful session info grace period", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)

		w := NewTestWorker(t, &TestWorkerOpts{
			DisableAutoStart: true,
			Name:             "close non active sessions and connections",
		})
		// Ensure the recorder manager is not used
		w.Worker().recorderManager = nil

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(err)
		cc, err := grpc.Dial(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(err)

		mockSessionClient := pbs.NewMockSessionServiceClient()
		mockSessionClient.CloseConnectionFn = func(ctx context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
			return &pbs.CloseConnectionResponse{}, nil
		}
		sm := session.NewTestManager(t, mockSessionClient)
		sm.StoreSession("s_1234567890")
		sm.StoreConnection(t, "s_1234567890", "c_1234567890")
		w.Worker().sessionManager = sm

		serverInvoked := false
		fakeServer := &mockServerCoordinationService{
			nextSessionInfoAssert: func(req *pbs.SessionInfoRequest) (*pbs.SessionInfoResponse, error) {
				serverInvoked = true
				assert.Equal("w_1234567890", req.WorkerId)
				require.Len(req.Sessions, 1)
				assert.Equal("s_1234567890", req.Sessions[0].SessionId)
				return &pbs.SessionInfoResponse{}, errors.New("connection timeout")
			},
		}

		srv := grpc.NewServer()
		pbs.RegisterServerCoordinationServiceServer(srv, fakeServer)
		w.Worker().GrpcClientConn.Store(cc)
		w.Worker().lastRoutingInfoSuccess.Store(&LastRoutingInfo{
			RoutingInfoResponse: &pbs.RoutingInfoResponse{
				WorkerId: "w_1234567890",
			},
		})
		// Set the status time of the last successful session information
		// to a value that ensures we have surpassed the grace period time.
		gracePeriod := time.Duration(w.Worker().successfulSessionInfoGracePeriod.Load()) + (5 * time.Second)
		w.Worker().lastSessionInfoSuccess.Store(&lastSessionInfo{
			LastSuccessfulRequestTime: time.Now().Add(-gracePeriod),
		})

		serverStarted := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			close(serverStarted)
			assert.NoError(srv.Serve(ln))
		}()

		<-serverStarted
		actualErr := w.Worker().sendSessionInfo(context.Background())

		require.Error(actualErr)
		assert.ErrorContains(actualErr, "connection timeout")
		assert.True(serverInvoked)
		localSession := w.Worker().sessionManager.Get("s_1234567890")
		require.NotNil(localSession)
		assert.Equal(pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE, localSession.GetStatus())
		localConnections := localSession.GetLocalConnections()
		require.NotEmpty(localConnections)
		c, ok := localConnections["c_1234567890"]
		require.True(ok)
		require.NotNil(c)
		assert.Equal(pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED, c.Status)

		srv.GracefulStop()
		wg.Wait()
	})
}
