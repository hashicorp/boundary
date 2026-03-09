// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/stretchr/testify/require"
)

func TestStartListeners(t *testing.T) {
	testNonTlsRejected := func(t *testing.T, resp *http.Response, err error) {
		require.Error(t, err)
	}

	tests := []struct {
		name           string
		proxyListeners []*listenerutil.ListenerConfig
		expErr         bool
		expErrMsg      string
		assertions     func(t *testing.T, w *Worker, addr string)
	}{
		{
			name: "unix listener",
			proxyListeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"proxy"},
					Address:    "/tmp/boundary-worker-test-start-listeners.sock",
					TLSDisable: true,
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker, addr string) {
				cl := http.Client{
					Transport: &http.Transport{
						Dial: func(network, addr string) (net.Conn, error) { return net.Dial("unix", addr) },
					},
				}
				resp, err := cl.Get("http://anything.domain/v1/proxy/")
				testNonTlsRejected(t, resp, err)
			},
		},
		{
			name: "tcp listener",
			proxyListeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"proxy"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker, addr string) {
				resp, err := http.Get("http://" + addr + "/v1/proxy/")
				testNonTlsRejected(t, resp, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := NewTestWorker(t, &TestWorkerOpts{DisableAutoStart: true}).w.conf
			conf.RawConfig.SharedConfig.Listeners = tt.proxyListeners

			err := conf.SetupListeners(nil, conf.RawConfig.SharedConfig, []string{"proxy"})
			require.NoError(t, err)

			ctx := context.Background()
			w, err := New(ctx, conf)
			require.NoError(t, err)
			w.baseContext = ctx

			var dummyClientProducer handlers.UpstreamMessageServiceClientProducer
			dummyClientProducer = func(ctx context.Context) (pbs.UpstreamMessageServiceClient, error) {
				panic("stubbed producer: not used in this test")
			}
			w.controllerUpstreamMsgConn.Store(&dummyClientProducer)

			manager, err := session.NewManager(pbs.NewSessionServiceClient(w.GrpcClientConn.Load()))
			require.NoError(t, err)
			err = w.startListeners(manager)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				return
			}

			require.NoError(t, err)

			if tt.assertions != nil {
				tt.assertions(t, w, w.proxyListener.ProxyListener.Addr().String())
			}
		})
	}
}

func TestStopHttpServersAndListeners(t *testing.T) {
	tests := []struct {
		name       string
		workerFn   func(t *testing.T) *Worker
		assertions func(t *testing.T, w *Worker)
		expErr     bool
		expErrStr  string
	}{
		{
			name: "no listeners",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{proxyListener: &base.ServerListener{}}
			},
			expErr: false,
		},
		{
			name: "nil listeners slice",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{proxyListener: nil}
			},
			expErr: false,
		},
		{
			name: "listeners with nil http server",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{
					proxyListener: &base.ServerListener{
						HTTPServer: nil,
					},
				}
			},
			expErr: false,
		},
		{
			name: "valid listener with http server",
			workerFn: func(t *testing.T) *Worker {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				s1 := &http.Server{}

				go s1.Serve(l1)

				// Make sure they're up
				_, err = http.Get("http://" + l1.Addr().String())
				require.NoError(t, err)

				return &Worker{
					baseContext: context.Background(),
					proxyListener: &base.ServerListener{
						ProxyListener: l1,
						HTTPServer:    s1,
						Config:        &listenerutil.ListenerConfig{Type: "tcp"},
					},
				}
			},
			assertions: func(t *testing.T, w *Worker) {
				// Asserts the HTTP Servers are closed.
				require.ErrorIs(t, w.proxyListener.HTTPServer.Serve(w.proxyListener.ProxyListener), http.ErrServerClosed)

				// Asserts the underlying listeners are closed.
				require.ErrorIs(t, w.proxyListener.ProxyListener.Close(), net.ErrClosed)
			},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := tt.workerFn(t)
			err := w.stopServersAndListeners()
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				return
			}

			require.NoError(t, err)
			if tt.assertions != nil {
				tt.assertions(t, w)
			}
		})
	}
}

func TestStopAnyListeners(t *testing.T) {
	tests := []struct {
		name       string
		workerFn   func(t *testing.T) *Worker
		assertions func(t *testing.T, w *Worker)
		expErr     bool
		expErrStr  string
	}{
		{
			name: "nil listeners",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{proxyListener: nil}
			},
			expErr: false,
		},
		{
			name: "no listeners",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{proxyListener: &base.ServerListener{}}
			},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.workerFn(t)
			err := c.stopAnyListeners()
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				return
			}

			require.NoError(t, err)
			if tt.assertions != nil {
				tt.assertions(t, c)
			}
		})
	}
}

func TestListenerCloseErrorCheck(t *testing.T) {
	tests := []struct {
		name   string
		lnType string
		err    error
		expErr error
	}{
		{
			name:   "nil err",
			lnType: "tcp",
			err:    nil,
			expErr: nil,
		},
		{
			name:   "net.Closed",
			lnType: "tcp",
			err:    net.ErrClosed,
			expErr: nil,
		},
		{
			name:   "path err not unix type",
			lnType: "tcp",
			err:    &os.PathError{Op: "test"},
			expErr: &os.PathError{Op: "test"},
		},
		{
			name:   "path err unix type",
			lnType: "unix",
			err:    &os.PathError{Op: "test"},
			expErr: nil,
		},
		{
			name:   "literally anything else",
			lnType: "tcp",
			err:    fmt.Errorf("oops I errored"),
			expErr: fmt.Errorf("oops I errored"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := listenerCloseErrorCheck(tt.lnType, tt.err)
			require.Equal(t, tt.expErr, err)
		})
	}
}
