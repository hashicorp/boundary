// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ops

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/health"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	pbs "github.com/hashicorp/boundary/internal/gen/ops/services"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestNewServer(t *testing.T) {
	tests := []struct {
		name       string
		logger     hclog.Logger
		c          *controller.Controller
		w          *worker.Worker
		listeners  []*base.ServerListener
		assertions func(t *testing.T, s *Server)
		expErr     bool
		expErrMsg  string
	}{
		{
			name:      "nil logger",
			logger:    nil,
			listeners: []*base.ServerListener{{}},
			expErr:    true,
			expErrMsg: "ops.NewServer(): missing logger",
		},
		{
			name:      "nil ServerListeners",
			logger:    hclog.Default(),
			listeners: nil,
			expErr:    false,
			assertions: func(t *testing.T, s *Server) {
				require.Len(t, s.bundles, 0)
			},
		},
		{
			name:      "empty ServerListeners",
			logger:    hclog.Default(),
			listeners: []*base.ServerListener{},
			expErr:    false,
			assertions: func(t *testing.T, s *Server) {
				require.Len(t, s.bundles, 0)
			},
		},
		{
			name:      "nil listeners",
			logger:    hclog.Default(),
			listeners: []*base.ServerListener{nil, nil},
			expErr:    false,
			assertions: func(t *testing.T, s *Server) {
				require.Len(t, s.bundles, 0)
			},
		},
		{
			name:   "listeners with nil config",
			logger: hclog.Default(),
			listeners: []*base.ServerListener{
				{
					Config: nil,
				},
				{
					Config: nil,
				},
			},
			expErr: false,
			assertions: func(t *testing.T, s *Server) {
				require.Len(t, s.bundles, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewServer(context.Background(), tt.logger, tt.c, tt.w, tt.listeners...)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, s)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, s)

			if tt.assertions != nil {
				tt.assertions(t, s)
			}
		})
	}
}

func TestNewServerIntegration(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T)
		listeners  []*listenerutil.ListenerConfig
		assertions func(t *testing.T, addrs []string)
		expErr     bool
		expErrMsg  string
	}{
		{
			name: "one tcp ops ipv4 listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"ops"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
			},
			assertions: func(t *testing.T, addrs []string) {
				resp, err := http.Get("http://" + addrs[0])
				resp.Body.Close()
				require.NoError(t, err)
			},
		},
		{
			name: "one tcp ops ipv6 listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"ops"},
					Address:    "[::1]:0",
					TLSDisable: true,
				},
			},
			assertions: func(t *testing.T, addrs []string) {
				resp, err := http.Get("http://" + addrs[0])
				resp.Body.Close()
				require.NoError(t, err)
			},
		},
		{
			name: "multiple tcp ops listeners",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"ops"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:       "tcp",
					Purpose:    []string{"ops"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
			},
			assertions: func(t *testing.T, addrs []string) {
				resp, err := http.Get("http://" + addrs[0])
				resp.Body.Close()
				require.NoError(t, err)

				resp, err = http.Get("http://" + addrs[1])
				resp.Body.Close()
				require.NoError(t, err)
			},
		},
		{
			name: "one unix socket ops listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"ops"},
					Address:    fmt.Sprintf("/tmp/boundary-opslistener-test-%s.sock", base62.MustRandom(5)),
					TLSDisable: true,
				},
			},
			expErr: false,
			assertions: func(t *testing.T, addrs []string) {
				conn, err := net.Dial("unix", addrs[0])
				require.NoError(t, err)
				t.Cleanup(func() { conn.Close() })

				cl := http.Client{
					Transport: &http.Transport{
						Dial: func(network, addr string) (net.Conn, error) { return conn, nil },
					},
				}
				_, err = cl.Get("http://random.domain")
				require.NoError(t, err)
			},
		},
		{
			name: "multiple unix socket ops listeners",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"ops"},
					Address:    fmt.Sprintf("/tmp/boundary-opslistener-test-%s.sock", base62.MustRandom(5)),
					TLSDisable: true,
				},
				{
					Type:       "unix",
					Purpose:    []string{"ops"},
					Address:    fmt.Sprintf("/tmp/boundary-opslistener-test-%s.sock", base62.MustRandom(5)),
					TLSDisable: true,
				},
			},
			expErr: false,
			assertions: func(t *testing.T, addrs []string) {
				for _, addr := range addrs {
					conn, err := net.Dial("unix", addr)
					require.NoError(t, err)
					t.Cleanup(func() { conn.Close() })

					cl := http.Client{
						Transport: &http.Transport{
							Dial: func(network, addr string) (net.Conn, error) { return conn, nil },
						},
					}
					_, err = cl.Get("http://random.domain")
					require.NoError(t, err)
				}
			},
		},
		{
			name: "multiple tcp ops listeners (tls)",
			setup: func(t *testing.T) {
				testTlsSetup(t, "./boundary-opslistener-cert1.cert", "./boundary-opslistener-pk1.key")
				testTlsSetup(t, "./boundary-opslistener-cert2.cert", "./boundary-opslistener-pk2.key")
			},
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:        "tcp",
					Purpose:     []string{"ops"},
					Address:     "127.0.0.1:0",
					TLSKeyFile:  "./boundary-opslistener-pk1.key",
					TLSCertFile: "./boundary-opslistener-cert1.cert",
				},
				{
					Type:        "tcp",
					Purpose:     []string{"ops"},
					Address:     "127.0.0.1:0",
					TLSKeyFile:  "./boundary-opslistener-pk2.key",
					TLSCertFile: "./boundary-opslistener-cert2.cert",
				},
			},
			assertions: func(t *testing.T, addrs []string) {
				cl := testTlsHttpClient(t, "./boundary-opslistener-cert1.cert")
				_, err := cl.Get("https://" + addrs[0])
				require.NoError(t, err)

				cl = testTlsHttpClient(t, "./boundary-opslistener-cert2.cert")
				_, err = cl.Get("https://" + addrs[1])
				require.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}

			bs := &base.Server{ // These fields are only needed to successfully call `SetupListeners`
				Info:            make(map[string]string),
				ReloadFuncs:     make(map[string][]reloadutil.ReloadFunc),
				ReloadFuncsLock: &sync.RWMutex{},
				Logger:          hclog.Default(),
			}
			err := bs.SetupListeners(nil, &configutil.SharedConfig{Listeners: tt.listeners}, []string{"ops"})
			require.NoError(t, err)

			s, err := NewServer(context.Background(), hclog.Default(), nil, nil, bs.Listeners...)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, s)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, s)
			s.Start()
			t.Cleanup(func() {
				if err := s.Shutdown(); err != nil {
					t.Logf("error shutting down: %v", err)
				}
			})

			addrs := make([]string, 0, len(s.bundles))
			for _, b := range s.bundles {
				addrs = append(addrs, b.ln.OpsListener.Addr().String())
			}
			if tt.assertions != nil {
				tt.assertions(t, addrs)
			}
		})
	}
}

func TestShutdown(t *testing.T) {
	tests := []struct {
		name        string
		opsServerFn func(t *testing.T) *Server
		assertions  func(t *testing.T, o *Server)
		expErr      bool
		expErrStr   string
	}{
		{
			name: "nil bundle slice",
			opsServerFn: func(t *testing.T) *Server {
				return &Server{bundles: nil}
			},
			expErr: false, // No-op
		},
		{
			name: "empty bundle slice",
			opsServerFn: func(t *testing.T) *Server {
				return &Server{bundles: []*opsBundle{}}
			},
			expErr: false, // No-op
		},
		{
			name: "nil bundle",
			opsServerFn: func(t *testing.T) *Server {
				return &Server{bundles: []*opsBundle{nil}}
			},
			expErr:    true,
			expErrStr: "ops.(Server).Shutdown: missing bundle, listener or its fields",
		},
		{
			name: "empty bundle",
			opsServerFn: func(t *testing.T) *Server {
				return &Server{bundles: []*opsBundle{{}}}
			},
			expErr:    true,
			expErrStr: "ops.(Server).Shutdown: missing bundle, listener or its fields",
		},
		{
			name: "missing listener config",
			opsServerFn: func(t *testing.T) *Server {
				return &Server{
					bundles: []*opsBundle{
						{
							ln: &base.ServerListener{
								HTTPServer: &http.Server{},
							},
						},
					},
				}
			},
			expErr:    true,
			expErrStr: "ops.(Server).Shutdown: missing bundle, listener or its fields",
		},
		{
			name: "missing listener mux",
			opsServerFn: func(t *testing.T) *Server {
				return &Server{
					bundles: []*opsBundle{
						{
							ln: &base.ServerListener{
								Config:     &listenerutil.ListenerConfig{},
								HTTPServer: &http.Server{},
							},
						},
					},
				}
			},
			expErr:    true,
			expErrStr: "ops.(Server).Shutdown: missing bundle, listener or its fields",
		},
		{
			name: "missing http server",
			opsServerFn: func(t *testing.T) *Server {
				return &Server{
					bundles: []*opsBundle{
						{
							ln: &base.ServerListener{
								Config: &listenerutil.ListenerConfig{},
							},
						},
					},
				}
			},
			expErr:    true,
			expErrStr: "ops.(Server).Shutdown: missing bundle, listener or its fields",
		},
		{
			name: "listener already closed",
			opsServerFn: func(t *testing.T) *Server {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				require.NoError(t, l1.Close())

				s1 := &http.Server{}
				return &Server{
					bundles: []*opsBundle{
						{
							ln: &base.ServerListener{
								HTTPServer:  s1,
								OpsListener: l1,
								Config:      &listenerutil.ListenerConfig{Type: "tcp", Purpose: []string{"ops"}},
							},
						},
					},
				}
			},
			assertions: func(t *testing.T, s *Server) {
				// The HTTP Server must be closed.
				require.ErrorIs(t, s.bundles[0].ln.HTTPServer.Serve(s.bundles[0].ln.OpsListener), http.ErrServerClosed)

				// The underlying listener must be closed.
				require.ErrorIs(t, s.bundles[0].ln.OpsListener.Close(), net.ErrClosed)
			},
			expErr: false,
		},
		{
			name: "http server already closed",
			opsServerFn: func(t *testing.T) *Server {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				s1 := &http.Server{}
				// Use error channel so that we can use test assertions on the returned error.
				// It is illegal to call `t.FailNow()` from a goroutine.
				// https://pkg.go.dev/testing#T.FailNow
				errChan := make(chan error)
				go func() {
					errChan <- s1.Serve(l1)
				}()
				t.Cleanup(func() {
					// Will block until we stopped serving
					require.ErrorIs(t, <-errChan, http.ErrServerClosed)
				})
				err = s1.Shutdown(context.Background())
				require.NoError(t, err)

				return &Server{
					bundles: []*opsBundle{
						{
							ln: &base.ServerListener{
								OpsListener: l1,
								HTTPServer:  s1,
								Config:      &listenerutil.ListenerConfig{Type: "tcp", Purpose: []string{"ops"}},
							},
						},
					},
				}
			},
			assertions: func(t *testing.T, s *Server) {
				// The HTTP Server must be closed.
				require.ErrorIs(t, s.bundles[0].ln.HTTPServer.Serve(s.bundles[0].ln.OpsListener), http.ErrServerClosed)

				// The underlying listener must be closed.
				require.ErrorIs(t, s.bundles[0].ln.OpsListener.Close(), net.ErrClosed)
			},
		},
		{
			name: "multiple bundles to close",
			opsServerFn: func(t *testing.T) *Server {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				s1 := &http.Server{}
				// Use error channel so that we can use test assertions on the returned error.
				// It is illegal to call `t.FailNow()` from a goroutine.
				// https://pkg.go.dev/testing#T.FailNow
				s1ErrChan := make(chan error)
				go func() {
					s1ErrChan <- s1.Serve(l1)
				}()
				t.Cleanup(func() {
					require.ErrorIs(t, <-s1ErrChan, http.ErrServerClosed)
				})

				l2, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				s2 := &http.Server{}
				s2ErrChan := make(chan error)
				go func() {
					s2ErrChan <- s2.Serve(l2)
				}()
				t.Cleanup(func() {
					require.ErrorIs(t, <-s2ErrChan, http.ErrServerClosed)
				})

				return &Server{
					bundles: []*opsBundle{
						{
							ln: &base.ServerListener{
								OpsListener: l1,
								HTTPServer:  s1,
								Config:      &listenerutil.ListenerConfig{Type: "tcp", Purpose: []string{"ops"}},
							},
						},
						{
							ln: &base.ServerListener{
								OpsListener: l2,
								HTTPServer:  s2,
								Config:      &listenerutil.ListenerConfig{Type: "tcp", Purpose: []string{"ops"}},
							},
						},
					},
				}
			},
			assertions: func(t *testing.T, s *Server) {
				// The HTTP Server must be closed.
				require.ErrorIs(t, s.bundles[0].ln.HTTPServer.Serve(s.bundles[0].ln.OpsListener), http.ErrServerClosed)
				require.ErrorIs(t, s.bundles[1].ln.HTTPServer.Serve(s.bundles[1].ln.OpsListener), http.ErrServerClosed)

				// The underlying listener must be closed.
				require.ErrorIs(t, s.bundles[0].ln.OpsListener.Close(), net.ErrClosed)
				require.ErrorIs(t, s.bundles[1].ln.OpsListener.Close(), net.ErrClosed)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.opsServerFn(t)
			err := o.Shutdown()
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				return
			}

			require.NoError(t, err)
			if tt.assertions != nil {
				tt.assertions(t, o)
			}
		})
	}
}

func TestHealthEndpointLifecycle(t *testing.T) {
	listeners := []*listenerutil.ListenerConfig{
		{
			Type:       "tcp",
			Address:    "127.0.0.1:0",
			Purpose:    []string{"ops"},
			TLSDisable: true,
		},

		// We only care about the ops listener, but the following
		// listeners are required to start a Controller.
		{
			Type:       "tcp",
			Address:    "127.0.0.1:0",
			Purpose:    []string{"api"},
			TLSDisable: true,
		},
		{
			Type:    "tcp",
			Address: "127.0.0.1:0",
			Purpose: []string{"cluster"},
		},
	}

	// Get test a controller so we can actually start a controller.
	tc := controller.NewTestController(t, &controller.TestControllerOpts{DisableAutoStart: true})
	tc.Config().RawConfig.SharedConfig.Listeners = listeners // Override with our own listeners.

	// Setup listeners that we've set up above to turn them into correct `ServerListener` objects
	// that the controller can handle. This will set `Server.Listeners`.
	err := tc.Server().SetupListeners(nil, tc.Config().RawConfig.SharedConfig, []string{"api", "cluster", "ops"})
	require.NoError(t, err)

	// Start controller. This sets `cmd.controller`.
	err = tc.Controller().Start()
	require.NoError(t, err)

	// Controller has started and is set onto our Command object, start ops.
	opsServer, err := NewServer(tc.Context(), hclog.Default(), tc.Controller(), nil, tc.Config().Listeners...)
	require.NoError(t, err)
	opsServer.Start()

	// Assert the ops endpoint is up and returning 200 OK.
	rsp, err := http.Get("http://" + tc.Config().Listeners[0].OpsListener.Addr().String() + "/health")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)

	// Start replying with 503 Service Unavailable from the health endpoint.
	tc.Controller().HealthService.StartServiceUnavailableReplies()

	// Assert we're receiving 503 Service Unavailable now instead of 200 OK.
	rsp, err = http.Get("http://" + tc.Config().Listeners[0].OpsListener.Addr().String() + "/health")
	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, rsp.StatusCode)
}

func TestWaitIfHealthExists(t *testing.T) {
	tests := []struct {
		name        string
		bundles     []*opsBundle
		gracePeriod time.Duration
		controller  *controller.Controller
		expMinWait  time.Duration
		expMaxWait  time.Duration
	}{
		{
			name:        "nil bundles",
			bundles:     nil,
			controller:  &controller.Controller{HealthService: &health.Service{}},
			gracePeriod: 1 * time.Minute,
			expMinWait:  0 * time.Second,
			expMaxWait:  500 * time.Microsecond,
		},
		{
			name:        "no bundles",
			bundles:     []*opsBundle{},
			controller:  &controller.Controller{HealthService: &health.Service{}},
			gracePeriod: 1 * time.Minute,
			expMinWait:  0 * time.Second,
			expMaxWait:  500 * time.Microsecond,
		},
		{
			name:        "nil controller",
			controller:  nil,
			gracePeriod: 1 * time.Minute,
			expMinWait:  0 * time.Second,
			expMaxWait:  500 * time.Microsecond,
		},
		{
			name:        "controller with no health service",
			controller:  &controller.Controller{HealthService: nil},
			gracePeriod: 1 * time.Minute,
			expMinWait:  0 * time.Second,
			expMaxWait:  500 * time.Microsecond,
		},
		{
			name:       "no grace period set",
			controller: &controller.Controller{HealthService: &health.Service{}},
			expMinWait: 0 * time.Second,
			expMaxWait: 500 * time.Microsecond,
		},
		{
			name:        "wait 500ms",
			bundles:     []*opsBundle{{}},
			controller:  &controller.Controller{HealthService: &health.Service{}},
			gracePeriod: 500 * time.Millisecond,
			expMinWait:  500 * time.Millisecond,
			expMaxWait:  600 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Server{
				bundles:    tt.bundles,
				controller: tt.controller,
			}

			start := time.Now()
			s.WaitIfHealthExists(tt.gracePeriod, cli.NewMockUi())
			actualWait := time.Since(start)

			require.GreaterOrEqual(t, actualWait, tt.expMinWait)
			require.LessOrEqual(t, actualWait, tt.expMaxWait)
		})
	}
}

func TestCreateOpsHandler(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name            string
		setupController bool
		setupWorker     bool
		lncfg           *listenerutil.ListenerConfig
		expErr          bool
		expErrMsg       string
		assertions      func(t *testing.T, addr string)
	}{
		{
			name:            "no controller set",
			setupController: false,
			lncfg:           &listenerutil.ListenerConfig{},
			assertions: func(t *testing.T, addr string) {
				rsp, err := http.Get("http://" + addr + "/health")
				require.NoError(t, err)                               // We can do the GET request
				require.Equal(t, http.StatusNotFound, rsp.StatusCode) // But the endpoint doesn't exist
			},
		},
		{
			name:            "controller set",
			setupController: true,
			lncfg:           &listenerutil.ListenerConfig{},
			assertions: func(t *testing.T, addr string) {
				rsp, err := http.Get("http://" + addr + "/health")
				require.NoError(t, err)                         // We can do the GET request
				require.Equal(t, http.StatusOK, rsp.StatusCode) // And the endpoint exists
				body, err := io.ReadAll(rsp.Body)
				require.NoError(t, err)
				assert.EqualValues(t, []byte("{}"), body)

				rsp, err = http.Get("http://" + addr + "/health?worker_info=1")
				require.NoError(t, err)                         // We can do the GET request
				require.Equal(t, http.StatusOK, rsp.StatusCode) // And the endpoint exists
				body, err = io.ReadAll(rsp.Body)
				require.NoError(t, err)
				assert.EqualValues(t, []byte("{}"), body)
			},
		},
		{
			name:        "worker set",
			setupWorker: true,
			lncfg:       &listenerutil.ListenerConfig{},
			assertions: func(t *testing.T, addr string) {
				rsp, err := http.Get("http://" + addr + "/health")
				require.NoError(t, err)                         // We can do the GET request
				require.Equal(t, http.StatusOK, rsp.StatusCode) // And the endpoint exists
				body, err := io.ReadAll(rsp.Body)
				require.NoError(t, err)
				assert.EqualValues(t, []byte("{}"), body)

				rsp, err = http.Get("http://" + addr + "/health?worker_info=1")
				require.NoError(t, err)                         // We can do the GET request
				require.Equal(t, http.StatusOK, rsp.StatusCode) // And the endpoint exists
				pbResp := &pbs.GetHealthResponse{}
				body, err = io.ReadAll(rsp.Body)
				require.NoError(t, err)
				require.NoError(t, protojson.Unmarshal(body, pbResp))
				want := &pbs.GetHealthResponse{WorkerProcessInfo: &pbhealth.HealthInfo{
					State:              server.ActiveOperationalState.String(),
					ActiveSessionCount: wrapperspb.UInt32(0),
				}}
				assert.Empty(t,
					cmp.Diff(
						want,
						pbResp,
						protocmp.Transform(),
						protocmp.IgnoreFields(&pbhealth.HealthInfo{}, "upstream_connection_state"),
					),
				)
			},
		},
		{
			name:            "worker and controller set",
			setupController: true,
			setupWorker:     true,
			lncfg:           &listenerutil.ListenerConfig{},
			assertions: func(t *testing.T, addr string) {
				rsp, err := http.Get("http://" + addr + "/health")
				require.NoError(t, err)                         // We can do the GET request
				require.Equal(t, http.StatusOK, rsp.StatusCode) // And the endpoint exists
				body, err := io.ReadAll(rsp.Body)
				require.NoError(t, err)
				assert.EqualValues(t, []byte("{}"), body)
				rsp, err = http.Get("http://" + addr + "/health?worker_info=1")
				require.NoError(t, err)                         // We can do the GET request
				require.Equal(t, http.StatusOK, rsp.StatusCode) // And the endpoint exists
				pbResp := &pbs.GetHealthResponse{}
				body, err = io.ReadAll(rsp.Body)
				require.NoError(t, err)
				require.NoError(t, protojson.Unmarshal(body, pbResp))
				want := &pbs.GetHealthResponse{WorkerProcessInfo: &pbhealth.HealthInfo{
					State:              server.ActiveOperationalState.String(),
					ActiveSessionCount: wrapperspb.UInt32(0),
				}}
				assert.Empty(t,
					cmp.Diff(
						want,
						pbResp,
						protocmp.Transform(),
						protocmp.IgnoreFields(&pbhealth.HealthInfo{}, "upstream_connection_state"),
					),
				)
			},
		},
		{
			name:            "controller set, but nil listener config",
			setupController: true,
			lncfg:           nil,
			expErr:          true,
			expErrMsg:       "controller.(Controller).GetHealthHandler: received nil listener config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c *controller.Controller
			if tt.setupController {
				tc := controller.NewTestController(t, &controller.TestControllerOpts{})

				c = tc.Controller()
			}
			var w *worker.Worker
			if tt.setupWorker {
				tc := worker.NewTestWorker(t, &worker.TestWorkerOpts{})
				w = tc.Worker()
			}

			h, err := createOpsHandler(ctx, tt.lncfg, c, w)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				require.Nil(t, h)
				return
			}

			require.NoError(t, err)

			s := http.Server{Handler: h}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			go s.Serve(l)

			t.Cleanup(func() {
				require.NoError(t, s.Shutdown(ctx))
			})

			tt.assertions(t, l.Addr().String())
		})
	}
}

func TestCreateHttpServer(t *testing.T) {
	tests := []struct {
		name       string
		lncfg      *listenerutil.ListenerConfig
		assertions func(t *testing.T, s *http.Server)
	}{
		{
			name:  "default values are set if none are set in listener config",
			lncfg: &listenerutil.ListenerConfig{},
			assertions: func(t *testing.T, s *http.Server) {
				require.Equal(t, 10*time.Second, s.ReadHeaderTimeout)
				require.Equal(t, 30*time.Second, s.ReadTimeout)
				require.Equal(t, 5*time.Minute, s.IdleTimeout)
			},
		},
		{
			name: "configured values are respected",
			lncfg: &listenerutil.ListenerConfig{
				HTTPReadHeaderTimeout: time.Minute,
				HTTPReadTimeout:       2 * time.Minute,
				HTTPWriteTimeout:      3 * time.Minute,
				HTTPIdleTimeout:       4 * time.Minute,
			},
			assertions: func(t *testing.T, s *http.Server) {
				require.Equal(t, time.Minute, s.ReadHeaderTimeout)
				require.Equal(t, 2*time.Minute, s.ReadTimeout)
				require.Equal(t, 3*time.Minute, s.WriteTimeout)
				require.Equal(t, 4*time.Minute, s.IdleTimeout)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := hclog.Default()

			s := createHttpServer(l, http.NotFoundHandler(), tt.lncfg)
			require.NotNil(t, s)
			require.NotNil(t, s.Handler)
			require.NotNil(t, s.ErrorLog)

			tt.assertions(t, s)
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

func testTlsSetup(t *testing.T, certPath, keyPath string) {
	t.Cleanup(func() {
		require.NoError(t, os.Remove(certPath))
		require.NoError(t, os.Remove(keyPath))
	})

	certBytes, _, priv := createTestCert(t)

	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))
	require.NoError(t, certFile.Close())

	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)

	marshaledKey, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: marshaledKey}))
	require.NoError(t, keyFile.Close())
}

func testTlsHttpClient(t *testing.T, certPath string) *http.Client {
	f, err := os.Open(certPath)
	require.NoError(t, err)

	certBytes, err := io.ReadAll(f)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certBytes)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}
}

func createTestCert(t *testing.T) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(5 * time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"/tmp/boundary-opslistener-test0.sock", "/tmp/boundary-opslistener-test1.sock"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	return certBytes, pub, priv
}
