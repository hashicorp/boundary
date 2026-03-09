// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/resolver/manual"
)

func TestMonitorUpstreamConnectionState(t *testing.T) {
	servers, err := createTestServers(t)
	require.NoError(t, err)

	scheme := strconv.FormatInt(time.Now().UnixNano(), 36)
	res := manual.NewBuilderWithScheme(scheme)

	t.Cleanup(func() {
		for _, s := range servers {
			s.srv.GracefulStop()
		}
	})

	tests := []struct {
		name          string
		addresses     []string
		expectedState connectivity.State
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
			stateCtx, cancelStateCtx := context.WithCancel(context.Background())
			upstreamConnectionState := new(atomic.Value)
			doneWait := make(chan struct{})

			grpcResolver := &grpcResolverReceiver{res}
			grpcResolver.InitialAddresses([]string{servers[0].address})

			dialOpts := createDefaultGRPCDialOptions(res, nil)
			cc, err := grpc.Dial(
				fmt.Sprintf("%s:///%s", res.Scheme(), servers[0].address),
				dialOpts...,
			)
			require.NoError(t, err)

			// track GRPC state changes
			go monitorUpstreamConnectionState(stateCtx, cc, upstreamConnectionState)

			grpcResolver.SetAddresses(tt.addresses)

			go waitForConnectionStateCondition(upstreamConnectionState, tt.expectedState, doneWait)

			select {
			case <-doneWait:
				// The connection condition was met, Proceed with assertions
			case <-time.After(2 * time.Second):
				t.Error("Time out waiting for condition")
			}

			require.NoError(t, cc.Close())
			cancelStateCtx()
		})
	}
}

func waitForConnectionStateCondition(upstreamConnectionState *atomic.Value, expectedValue connectivity.State, ch chan<- struct{}) {
	for {
		currentValue := upstreamConnectionState.Load()
		if expectedValue == currentValue {
			ch <- struct{}{}
			return
		}
		// Small delay for checking state
		time.Sleep(time.Millisecond)
	}
}

type serverTestInfo struct {
	srv      *grpc.Server
	address  string
	listener net.Listener
}

func createTestServers(t *testing.T) ([]*serverTestInfo, error) {
	serverCount := 4

	servers := make([]*serverTestInfo, 0, serverCount)
	for i := 0; i < serverCount; i++ {
		listener, err := nettest.NewLocalListener("tcp")
		if err != nil {
			return nil, err
		}
		srv := grpc.NewServer()
		lInfo := &serverTestInfo{srv: srv, listener: listener, address: listener.Addr().String()}
		servers = append(servers, lInfo)
	}
	for i := range servers {
		go func(num int) {
			if err := servers[num].srv.Serve(servers[num].listener); err != nil {
				t.Logf("error serving: %v", err)
			}
		}(i)
	}

	return servers, nil
}
