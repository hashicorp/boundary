// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cluster"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/protocol"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

func TestStartListeners(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T)
		listeners  []*listenerutil.ListenerConfig
		assertions func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string)
	}{
		{
			name: "one api, one cluster listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:0",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				rsp, err := http.Get("http://" + apiAddrs[0] + "/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)

				clusterGrpcDialNoError(t, c, "tcp", clusterAddr)
			},
		},
		{
			name: "multiple api, one cluster listeners",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:0",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				for _, apiAddr := range apiAddrs {
					rsp, err := http.Get("http://" + apiAddr + "/v1/auth-methods?scope_id=global")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, rsp.StatusCode)
				}

				clusterGrpcDialNoError(t, c, "tcp", clusterAddr)
			},
		},
		{
			name:  "one api (tls), one cluster listener",
			setup: testApiTlsSetup(t, "./boundary-startlistenerstest.cert", "./boundary-startlistenerstest.key"),
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:        "tcp",
					Purpose:     []string{"api"},
					Address:     "127.0.0.1:0",
					TLSCertFile: "./boundary-startlistenerstest.cert",
					TLSKeyFile:  "./boundary-startlistenerstest.key",
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:0",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				client := testTlsHttpClient(t, "./boundary-startlistenerstest.cert")
				rsp, err := client.Get("https://" + apiAddrs[0] + "/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)

				clusterGrpcDialNoError(t, c, "tcp", clusterAddr)
			},
		},
		{
			name: "multiple api (tls), one cluster listener",
			setup: func(t *testing.T) {
				testApiTlsSetup(t, "./boundary-startlistenerstest0.cert", "./boundary-startlistenerstest0.key")(t)
				testApiTlsSetup(t, "./boundary-startlistenerstest1.cert", "./boundary-startlistenerstest1.key")(t)
			},
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:        "tcp",
					Purpose:     []string{"api"},
					Address:     "127.0.0.1:0",
					TLSCertFile: "./boundary-startlistenerstest0.cert",
					TLSKeyFile:  "./boundary-startlistenerstest0.key",
				},
				{
					Type:        "tcp",
					Purpose:     []string{"api"},
					Address:     "127.0.0.1:0",
					TLSCertFile: "./boundary-startlistenerstest1.cert",
					TLSKeyFile:  "./boundary-startlistenerstest1.key",
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:0",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				for i, apiAddr := range apiAddrs {
					client := testTlsHttpClient(t, "./boundary-startlistenerstest"+strconv.Itoa(i)+".cert")
					rsp, err := client.Get("https://" + apiAddr + "/v1/auth-methods?scope_id=global")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, rsp.StatusCode)
				}

				clusterGrpcDialNoError(t, c, "tcp", clusterAddr)
			},
		},
		{
			name: "one api, one cluster listener on unix sockets",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test-api.sock",
					TLSDisable: true,
				},
				{
					Type:    "unix",
					Purpose: []string{"cluster"},
					Address: "/tmp/boundary-listener-test-cluster.sock",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				conn, err := net.Dial("unix", apiAddrs[0])
				require.NoError(t, err)

				cl := http.Client{
					Transport: &http.Transport{
						Dial: func(network, addr string) (net.Conn, error) { return conn, nil },
					},
				}
				rsp, err := cl.Get("http://randomdomain.boundary/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)
				require.NoError(t, conn.Close())

				clusterGrpcDialNoError(t, c, "unix", clusterAddr)
			},
		},
		{
			name: "multiple api, one cluster listener on unix sockets",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test-api.sock",
					TLSDisable: true,
				},
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test-api2.sock",
					TLSDisable: true,
				},
				{
					Type:    "unix",
					Purpose: []string{"cluster"},
					Address: "/tmp/boundary-listener-test-cluster.sock",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				for _, apiAddr := range apiAddrs {
					conn, err := net.Dial("unix", apiAddr)
					require.NoError(t, err)

					cl := http.Client{
						Transport: &http.Transport{
							Dial: func(network, addr string) (net.Conn, error) { return conn, nil },
						},
					}
					rsp, err := cl.Get("http://randomdomain.boundary/v1/auth-methods?scope_id=global")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, rsp.StatusCode)
					require.NoError(t, conn.Close())
				}

				clusterGrpcDialNoError(t, c, "unix", clusterAddr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}

			ctx, cancel := context.WithCancel(context.Background())

			debugEnabled := new(atomic.Bool)
			debugEnabled.Store(false)
			opts := &TestControllerOpts{
				EnableEventing:             false,
				WorkerAuthDebuggingEnabled: debugEnabled,
			}

			tc := &TestController{
				t:              t,
				ctx:            ctx,
				cancel:         cancel,
				opts:           opts,
				shutdownDoneCh: make(chan struct{}),
				shutdownOnce:   new(sync.Once),
			}
			t.Cleanup(func() { tc.Shutdown() })

			conf := TestControllerConfig(t, ctx, tc, opts)
			conf.RawConfig.SharedConfig = &configutil.SharedConfig{Listeners: tt.listeners, DisableMlock: true}

			err := conf.SetupListeners(nil, conf.RawConfig.SharedConfig, []string{"api", "cluster"})
			require.NoError(t, err)

			c, err := New(ctx, conf)
			require.NoError(t, err)

			c.baseContext = ctx
			c.baseCancel = cancel

			err = c.startListeners()
			require.NoError(t, err)

			apiAddrs := make([]string, 0)
			for _, l := range c.apiListeners {
				apiAddrs = append(apiAddrs, l.ApiListener.Addr().String())
			}
			tt.assertions(t, c, apiAddrs, c.clusterListener.ClusterListener.Addr().String())
		})
	}
}

func TestStopClusterGrpcServerAndListener(t *testing.T) {
	tests := []struct {
		name         string
		controllerFn func(t *testing.T) *Controller
		assertions   func(t *testing.T, c *Controller)
		expErr       bool
		expErrStr    string
	}{
		{
			name: "no cluster listener",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{}
			},
			expErr: false,
		},
		{
			name: "no cluster grpc server",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{clusterListener: &base.ServerListener{}}
			},
			expErr:    true,
			expErrStr: "no cluster grpc server",
		},
		{
			name: "no cluster listener mux",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{
					clusterListener: &base.ServerListener{
						GrpcServer: grpc.NewServer(),
						Config:     &listenerutil.ListenerConfig{Type: "tcp"},
					},
				}
			},
			expErr:    true,
			expErrStr: "no cluster listener",
		},
		{
			name: "listener already closed",
			controllerFn: func(t *testing.T) *Controller {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				require.NoError(t, l.Close())

				return &Controller{
					clusterListener: &base.ServerListener{
						ClusterListener: l,
						GrpcServer:      grpc.NewServer(),
						Config:          &listenerutil.ListenerConfig{Type: "tcp"},
					},
				}
			},
			assertions: func(t *testing.T, c *Controller) {
				require.ErrorIs(t, c.clusterListener.ClusterListener.Close(), net.ErrClosed)
			},
			expErr: false,
		},
		{
			name: "graceful stop",
			controllerFn: func(t *testing.T) *Controller {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				grpcServer := grpc.NewServer()
				go grpcServer.Serve(l)

				// Make sure it's up
				grpcCtx, grpcCtxCancel := context.WithTimeout(context.Background(), 5*time.Second)
				t.Cleanup(grpcCtxCancel)
				_, err = grpc.DialContext(grpcCtx,
					l.Addr().String(),
					grpc.WithTransportCredentials(insecure.NewCredentials()),
					grpc.WithBlock(),
				)
				require.NoError(t, err)

				return &Controller{
					clusterListener: &base.ServerListener{
						ClusterListener: l,
						GrpcServer:      grpcServer,
						Config:          &listenerutil.ListenerConfig{Type: "tcp"},
					},
				}
			},
			assertions: func(t *testing.T, c *Controller) {
				require.ErrorIs(t, c.clusterListener.ClusterListener.Close(), net.ErrClosed)
			},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.controllerFn(t)
			err := c.stopClusterGrpcServerAndListener()
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

func TestStopHttpServersAndListeners(t *testing.T) {
	tests := []struct {
		name         string
		controllerFn func(t *testing.T) *Controller
		assertions   func(t *testing.T, c *Controller)
		expErr       bool
		expErrStr    string
	}{
		{
			name: "no listeners",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{
					apiListeners: []*base.ServerListener{},
				}
			},
			expErr: false,
		},
		{
			name: "nil listeners",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{
					apiListeners: nil,
				}
			},
			expErr: false,
		},
		{
			name: "listeners with nil http server",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{
					apiListeners: []*base.ServerListener{
						{HTTPServer: nil},
						{HTTPServer: nil},
						{HTTPServer: nil},
					},
				}
			},
			expErr: false,
		},
		{
			name: "listener already closed",
			controllerFn: func(t *testing.T) *Controller {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				require.NoError(t, l1.Close())

				s1 := &http.Server{}
				return &Controller{
					baseContext: context.Background(),
					apiListeners: []*base.ServerListener{
						{
							ApiListener: l1,
							HTTPServer:  s1,
							Config:      &listenerutil.ListenerConfig{Type: "tcp"},
						},
					},
				}
			},
			assertions: func(t *testing.T, c *Controller) {
				// Asserts the HTTP Servers are closed.
				require.ErrorIs(t, c.apiListeners[0].HTTPServer.Serve(c.apiListeners[0].ApiListener), http.ErrServerClosed)

				// Asserts the underlying listeners are closed.
				require.ErrorIs(t, c.apiListeners[0].ApiListener.Close(), net.ErrClosed)
			},
			expErr: false,
		},
		{
			name: "multiple listeners",
			controllerFn: func(t *testing.T) *Controller {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				l2, err := net.Listen("unix", "/tmp/boundary-controller-TestStopHttpServersAndListeners-"+strconv.FormatInt(time.Now().UnixNano(), 10))
				require.NoError(t, err)

				s1 := &http.Server{}
				s2 := &http.Server{}

				go s1.Serve(l1)
				go s2.Serve(l2)

				// Make sure they're up
				_, err = http.Get("http://" + l1.Addr().String())
				require.NoError(t, err)

				c := http.Client{Transport: &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return net.Dial("unix", l2.Addr().String())
					},
				}}
				_, err = c.Get("http://random.domain")
				require.NoError(t, err)

				return &Controller{
					baseContext: context.Background(),
					apiListeners: []*base.ServerListener{
						{
							ApiListener: l1,
							HTTPServer:  s1,
							Config:      &listenerutil.ListenerConfig{Type: "tcp"},
						},
						{
							ApiListener: l2,
							HTTPServer:  s2,
							Config:      &listenerutil.ListenerConfig{Type: "tcp"},
						},
					},
				}
			},
			assertions: func(t *testing.T, c *Controller) {
				// Asserts the HTTP Servers are closed.
				require.ErrorIs(t, c.apiListeners[0].HTTPServer.Serve(c.apiListeners[0].ApiListener), http.ErrServerClosed)
				require.ErrorIs(t, c.apiListeners[1].HTTPServer.Serve(c.apiListeners[1].ApiListener), http.ErrServerClosed)

				// Asserts the underlying listeners are closed.
				require.ErrorIs(t, c.apiListeners[0].ApiListener.Close(), net.ErrClosed)
				require.ErrorIs(t, c.apiListeners[1].ApiListener.Close(), net.ErrClosed)
			},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.controllerFn(t)
			err := c.stopHttpServersAndListeners()
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

func TestStopApiGrpcServerAndListener(t *testing.T) {
	tests := []struct {
		name         string
		controllerFn func(t *testing.T) *Controller
		assertions   func(t *testing.T, c *Controller)
		expErr       bool
		expErrStr    string
	}{
		{
			name: "nil api grpc server",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{apiGrpcServer: nil}
			},
			expErr: false,
		},
		{
			name: "graceful stop",
			controllerFn: func(t *testing.T) *Controller {
				l := newGrpcServerListener()
				grpcServer := grpc.NewServer()

				go grpcServer.Serve(l)

				// Make sure it's up
				grpcCtx, grpcCtxCancel := context.WithTimeout(context.Background(), 10*time.Second)
				t.Cleanup(grpcCtxCancel)
				_, err := grpc.DialContext(grpcCtx,
					"",
					grpc.WithTransportCredentials(insecure.NewCredentials()),
					grpc.WithBlock(),
					grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
						return l.Dial()
					}),
				)
				require.NoError(t, err)
				return &Controller{apiGrpcServer: grpcServer, apiGrpcServerListener: l}
			},
			assertions: func(t *testing.T, c *Controller) {
				require.ErrorIs(t, c.apiGrpcServer.Serve(c.apiGrpcServerListener), grpc.ErrServerStopped)
			},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.controllerFn(t)
			err := c.stopApiGrpcServerAndListener()
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

func TestStopAnyListeners(t *testing.T) {
	tests := []struct {
		name         string
		controllerFn func(t *testing.T) *Controller
		assertions   func(t *testing.T, c *Controller)
		expErr       bool
		expErrStr    string
	}{
		{
			name: "nil apiListeners",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{apiListeners: nil}
			},
			expErr: false,
		},
		{
			name: "no listeners",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{apiListeners: []*base.ServerListener{}}
			},
			expErr: false,
		},
		{
			name: "nil listeners",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{apiListeners: []*base.ServerListener{nil, nil, nil}}
			},
			expErr: false,
		},
		{
			name: "non-empty listeners with nil listeners",
			controllerFn: func(t *testing.T) *Controller {
				return &Controller{apiListeners: []*base.ServerListener{
					{ClusterListener: nil}, {ClusterListener: nil}, {ClusterListener: nil},
				}}
			},
			expErr: false,
		},
		{
			name: "multiple listeners, including a closed one",
			controllerFn: func(t *testing.T) *Controller {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				l2, err := net.Listen("unix", "/tmp/boundary-controller-TestStopAnyListeners-"+strconv.FormatInt(time.Now().UnixNano(), 10))
				require.NoError(t, err)

				l3, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				require.NoError(t, l3.Close())

				return &Controller{apiListeners: []*base.ServerListener{
					{
						Config:      &listenerutil.ListenerConfig{Type: "tcp"},
						ApiListener: l1,
					},
					{
						Config:      &listenerutil.ListenerConfig{Type: "tcp"},
						ApiListener: l2,
					},
					{
						Config:      &listenerutil.ListenerConfig{Type: "tcp"},
						ApiListener: l3,
					},
				}}
			},
			assertions: func(t *testing.T, c *Controller) {
				for i := range c.apiListeners {
					ln := c.apiListeners[i]
					require.ErrorIs(t, ln.ApiListener.Close(), net.ErrClosed)
				}
			},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.controllerFn(t)
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

func clusterGrpcDialNoError(t *testing.T, c *Controller, network, addr string) {
	grpcConn, err := grpc.DialContext(
		context.Background(),
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(clusterTestDialer(t, c, network)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  time.Second,
				Multiplier: 1.2,
				Jitter:     0.2,
				MaxDelay:   3 * time.Second,
			},
		}),
	)
	require.NoError(t, err)
	require.NoError(t, grpcConn.Close())
}

func testApiTlsSetup(t *testing.T, certPath, keyPath string) func(t *testing.T) {
	return func(t *testing.T) {
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
}

func testTlsHttpClient(t *testing.T, filePath string) *http.Client {
	f, err := os.Open(filePath)
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
		DNSNames:              []string{"/tmp/boundary-listener-test-cluster.sock"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	return certBytes, pub, priv
}

func clusterTestDialer(t *testing.T, c *Controller, network string) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		storage, err := inmem.New(ctx)
		require.NoError(t, err)

		_, err = types.NewNodeCredentials(
			ctx,
			storage,
		)
		require.NoError(t, err)

		name, err := base62.Random(20)
		require.NoError(t, err)

		wci := &cluster.WorkerConnectionInfo{
			BoundaryVersion:  version.Get().VersionNumber(),
			Name:             strings.ToLower(name),
			OperationalState: server.ActiveOperationalState.String(),
		}
		st, err := wci.AsConnectionStateStruct()
		require.NoError(t, err)

		conn, err := protocol.Dial(
			ctx,
			storage,
			addr,
			nodeenrollment.WithState(st),
			nodeenrollment.WithRegistrationWrapper(c.conf.WorkerAuthKms),
			nodeenrollment.WithLogger(c.conf.Logger),
			nodeenrollment.WithWrappingRegistrationFlowApplicationSpecificParams(st),
		)
		if err != nil {
			log.Println(err)
		}
		require.NoError(t, err)
		return conn, nil
	}
}
