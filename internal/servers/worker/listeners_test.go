package worker

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

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
