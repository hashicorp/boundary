package worker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/libs/alpnmux"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/stretchr/testify/require"
)

func TestStartListeners(t *testing.T) {
	tests := []struct {
		name       string
		listeners  []*listenerutil.ListenerConfig
		expErr     bool
		expErrMsg  string
		assertions func(t *testing.T, w *Worker, addrs []string)
	}{
		{
			name: "one tcp listener, one unix listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"proxy"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:       "unix",
					Purpose:    []string{"proxy"},
					Address:    "/tmp/boundary-worker-test-start-listeners.sock",
					TLSDisable: true,
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker, addrs []string) {
				require.Len(t, addrs, 2)

				_, err := http.Get("http://" + addrs[0] + "/v1/proxy/")
				require.ErrorIs(t, err, io.EOF) // empty response because of worker tls request validation

				cl := http.Client{
					Transport: &http.Transport{
						Dial: func(network, addr string) (net.Conn, error) { return net.Dial("unix", addrs[1]) },
					},
				}
				_, err = cl.Get("http://anything.domain/v1/proxy/")
				require.ErrorIs(t, err, io.EOF) // empty response because of worker tls request validation
			},
		},
		{
			name: "multiple tcp listeners, multiple unix listeners",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"proxy"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:       "tcp",
					Purpose:    []string{"proxy"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:       "unix",
					Purpose:    []string{"proxy"},
					Address:    "/tmp/boundary-worker-test-start-listeners0.sock",
					TLSDisable: true,
				},
				{
					Type:       "unix",
					Purpose:    []string{"proxy"},
					Address:    "/tmp/boundary-worker-test-start-listeners1.sock",
					TLSDisable: true,
				},
			},
			expErr: false,
			assertions: func(t *testing.T, w *Worker, addrs []string) {
				require.Len(t, addrs, 4)

				_, err := http.Get("http://" + addrs[0] + "/v1/proxy/")
				require.ErrorIs(t, err, io.EOF) // empty response because of worker tls request validation

				_, err = http.Get("http://" + addrs[1] + "/v1/proxy/")
				require.ErrorIs(t, err, io.EOF) // empty response because of worker tls request validation

				for _, proxyAddr := range []string{addrs[2], addrs[3]} {
					cl := http.Client{
						Transport: &http.Transport{
							Dial: func(network, addr string) (net.Conn, error) { return net.Dial("unix", proxyAddr) },
						},
					}
					_, err = cl.Get("http://anything.domain/v1/proxy")
					require.ErrorIs(t, err, io.EOF) // empty response because of worker tls request validation
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := NewTestWorker(t, &TestWorkerOpts{DisableAutoStart: true}).w.conf
			conf.RawConfig.SharedConfig.Listeners = tt.listeners

			err := conf.SetupListeners(nil, conf.RawConfig.SharedConfig, []string{"proxy"})
			require.NoError(t, err)

			w, err := New(conf)
			require.NoError(t, err)
			w.baseContext = context.Background()

			err = w.startListeners()
			if tt.expErr {
				require.EqualError(t, err, tt.expErrMsg)
				return
			}

			require.NoError(t, err)

			addrs := make([]string, 0)
			for _, l := range w.listeners {
				addrs = append(addrs, l.Mux.Addr().String())
			}
			if tt.assertions != nil {
				tt.assertions(t, w, addrs)
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
				return &Worker{listeners: []*base.ServerListener{}}
			},
			expErr: false,
		},
		{
			name: "nil listeners slice",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{listeners: nil}
			},
			expErr: false,
		},
		{
			name: "listeners with nil http server",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{
					listeners: []*base.ServerListener{
						{HTTPServer: nil},
						{HTTPServer: nil},
						{HTTPServer: nil},
					},
				}
			},
			expErr: false,
		},
		{
			name: "multiple listeners",
			workerFn: func(t *testing.T) *Worker {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				l2, err := net.Listen("unix", "/tmp/boundary-worker-TestStopHttpServersAndListeners-"+strconv.FormatInt(time.Now().UnixNano(), 10))
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

				return &Worker{
					baseContext: context.Background(),
					listeners: []*base.ServerListener{
						{
							ALPNListener: l1,
							HTTPServer:   s1,
							Mux:          alpnmux.New(l1),
							Config:       &listenerutil.ListenerConfig{Type: "tcp"},
						},
						{
							ALPNListener: l2,
							HTTPServer:   s2,
							Mux:          alpnmux.New(l2),
							Config:       &listenerutil.ListenerConfig{Type: "tcp"},
						},
					},
				}
			},
			assertions: func(t *testing.T, w *Worker) {
				// Asserts the HTTP Servers are closed.
				require.ErrorIs(t, w.listeners[0].HTTPServer.Serve(w.listeners[0].ALPNListener), http.ErrServerClosed)
				require.ErrorIs(t, w.listeners[1].HTTPServer.Serve(w.listeners[1].ALPNListener), http.ErrServerClosed)

				// Asserts the underlying listeners are closed.
				require.ErrorIs(t, w.listeners[0].Mux.Close(), net.ErrClosed)
				require.ErrorIs(t, w.listeners[1].Mux.Close(), net.ErrClosed)
			},
			expErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := tt.workerFn(t)
			err := w.stopHttpServersAndListeners()
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
				return &Worker{listeners: nil}
			},
			expErr: false,
		},
		{
			name: "no listeners",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{listeners: []*base.ServerListener{}}
			},
			expErr: false,
		},
		{
			name: "listeners slice with nil server listeners",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{listeners: []*base.ServerListener{nil, nil, nil}}
			},
			expErr: false,
		},
		{
			name: "listeners with nil mux",
			workerFn: func(t *testing.T) *Worker {
				return &Worker{listeners: []*base.ServerListener{
					{Mux: nil}, {Mux: nil}, {Mux: nil},
				}}
			},
			expErr: false,
		},
		{
			name: "multiple listeners, including a closed one",
			workerFn: func(t *testing.T) *Worker {
				l1, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)

				l2, err := net.Listen("unix", "/tmp/boundary-worker-TestStopAnyListeners-"+strconv.FormatInt(time.Now().UnixNano(), 10))
				require.NoError(t, err)

				l3, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				require.NoError(t, l3.Close())

				return &Worker{listeners: []*base.ServerListener{
					{
						Config: &listenerutil.ListenerConfig{Type: "tcp"},
						Mux:    alpnmux.New(l1),
					},
					{
						Config: &listenerutil.ListenerConfig{Type: "tcp"},
						Mux:    alpnmux.New(l2),
					},
					{
						Config: &listenerutil.ListenerConfig{Type: "tcp"},
						Mux:    alpnmux.New(l3),
					},
				}}
			},
			assertions: func(t *testing.T, w *Worker) {
				for i := range w.listeners {
					ln := w.listeners[i]
					require.ErrorIs(t, ln.Mux.Close(), net.ErrClosed)
				}
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
