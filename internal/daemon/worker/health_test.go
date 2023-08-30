// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	opsservices "github.com/hashicorp/boundary/internal/gen/ops/services"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGetHealth(t *testing.T) {
	w := NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams: []string{"0.0.0.0"},
	})
	defer w.Shutdown()
	handler, err := w.Worker().GetHealthHandler()
	require.NoError(t, err)

	tests := []struct {
		name             string
		method           string
		queryParams      string
		expectedResponse *opsservices.GetHealthResponse
		expCode          int
	}{
		{
			name:             "healthy reply",
			method:           http.MethodGet,
			expCode:          http.StatusOK,
			expectedResponse: &opsservices.GetHealthResponse{},
		},
		{
			name:        "healthy reply with worker info",
			method:      http.MethodGet,
			queryParams: "worker_info=1",
			expCode:     http.StatusOK,
			expectedResponse: &opsservices.GetHealthResponse{
				WorkerProcessInfo: &pbhealth.HealthInfo{
					State:                     server.ActiveOperationalState.String(),
					ActiveSessionCount:        wrapperspb.UInt32(0),
					ControllerConnectionState: connectivity.TransientFailure.String(),
				},
			},
		},
		{
			name:             "Post request",
			method:           http.MethodPost,
			queryParams:      "worker_info=1",
			expCode:          http.StatusNotImplemented,
			expectedResponse: &opsservices.GetHealthResponse{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "/health"
			if tt.queryParams != "" {
				path = fmt.Sprintf("%s?%s", path, tt.queryParams)
			}
			req, err := http.NewRequest(tt.method, path, nil)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expCode, rr.Result().StatusCode)
			b, err := io.ReadAll(rr.Result().Body)
			require.NoError(t, err)
			resp := &opsservices.GetHealthResponse{}
			require.NoError(t, healthCheckMarshaler.Unmarshal(b, resp))

			assert.Empty(t, cmp.Diff(tt.expectedResponse, resp, protocmp.Transform()))
		})
	}
}

func TestWorkerHealth_ControllerConnectionState(t *testing.T) {
	ctx := context.Background()

	tw := NewTestWorker(t, &TestWorkerOpts{
		UseDeprecatedKmsAuthMethod: false,
	})

	w := tw.Worker()
	defer tw.Shutdown()
	handler, err := w.GetHealthHandler()
	require.NoError(t, err)

	servers := createTestServers(t)

	t.Cleanup(func() {
		w.Shutdown()

		for _, s := range servers {
			s.srv.GracefulStop()
		}
	})

	tests := []struct {
		name             string
		expectedResponse *opsservices.GetHealthResponse
		addresses        []string
		expectedState    connectivity.State
	}{
		{
			name:          "connection with 1 good address",
			addresses:     []string{servers[0].address},
			expectedState: connectivity.Ready,
		},
		{
			name:          "connection with multiple good addresses",
			addresses:     []string{servers[1].address, servers[2].address},
			expectedState: connectivity.Ready,
		},
		{
			name:          "connection with bad address",
			addresses:     []string{"bad_address"},
			expectedState: connectivity.TransientFailure,
		},
		{
			name:          "connection with 1 bad address and 1 good address",
			addresses:     []string{servers[0].address, "bad_address"},
			expectedState: connectivity.Ready,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w.updateAddresses(ctx, tt.addresses, &w.addressReceivers)

			// Add delay for connection state to update with GRPC manual resolver
			time.Sleep(2 * time.Second)

			path := "/health?worker_info=1"
			req, err := http.NewRequest(http.MethodGet, path, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Result().StatusCode)
			b, err := io.ReadAll(rr.Result().Body)
			require.NoError(t, err)

			resp := &opsservices.GetHealthResponse{}
			require.NoError(t, healthCheckMarshaler.Unmarshal(b, resp))

			assert.Equal(t, tt.expectedState.String(), resp.WorkerProcessInfo.ControllerConnectionState)
		})
	}
}

type serverTestInfo struct {
	srv             *grpc.Server
	acceptCount     int
	connClosedCount int
	address         string
	id              int
}

type testListener struct {
	net.Listener
	t    *testing.T
	info *serverTestInfo
}

func (l *testListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.info.acceptCount++
	return &testConn{Conn: c, t: l.t, info: l.info}, nil
}

type testConn struct {
	net.Conn
	t    *testing.T
	info *serverTestInfo
}

func (c *testConn) Close() error {
	c.info.connClosedCount++
	return c.Conn.Close()
}

func createTestServers(t *testing.T) []*serverTestInfo {
	serverCount := 4

	srvWg := sync.WaitGroup{}
	srvWg.Add(serverCount)
	servers := make([]*serverTestInfo, 0, serverCount)
	for i := 0; i < serverCount; i++ {
		l1, err := nettest.NewLocalListener("tcp")
		require.NoError(t, err)
		srv := grpc.NewServer()
		lInfo := &serverTestInfo{srv: srv, address: l1.Addr().String(), id: i + 1}
		tl := &testListener{Listener: l1, info: lInfo, t: t}
		servers = append(servers, lInfo)
		go func(i int) {
			defer srvWg.Done()
			servers[i].srv.Serve(tl)
		}(i)
	}

	return servers
}
