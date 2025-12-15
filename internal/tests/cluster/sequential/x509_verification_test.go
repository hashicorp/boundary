// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sequential

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	apiproxy "github.com/hashicorp/boundary/api/proxy"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestCustomX509Verification_Client(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	ec := event.TestEventerConfig(t, "TestWorkerReplay", event.TestWithObservationSink(t), event.TestWithSysSink(t))
	testLock := &sync.Mutex{}
	// This prevents us from running tests in parallel.
	server.TestUseCommunityFilterWorkersFn(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	req.NoError(event.InitSysEventer(logger, testLock, "use-TestCustomX509Verification", event.WithEventerConfig(&ec.EventerConfig)))
	t.Cleanup(func() {
		event.TestResetSystEventer(t)
	})
	t.Cleanup(func() {
		all, err := io.ReadAll(ec.AllEvents)
		require.NoError(t, err)
		t.Log(string(all))
	})

	conf, err := config.DevController()
	conf.Eventing = &ec.EventerConfig
	req.NoError(err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
	})

	conf, err = config.DevWorker()
	conf.Eventing = &ec.EventerConfig
	req.NoError(err)
	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:     c1.Config().WorkerAuthKms,
		InitialUpstreams:  c1.ClusterAddrs(),
		Logger:            logger.Named("w1"),
		WorkerRPCInterval: time.Second,
	})

	helper.ExpectWorkers(t, c1, w1)

	// Connect target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	req.NoError(err)
	req.NotNil(tgt)

	// Create test server, update default port on target
	ts := helper.NewTestTcpServer(t)
	require.NotNil(t, ts)
	t.Cleanup(ts.Close)
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(-1))
	req.NoError(err)
	req.NotNil(tgt)

	tests := []struct {
		name            string
		certPool        *x509.CertPool
		dnsName         *bytes.Buffer
		wantErrContains string
	}{
		{
			name: "base",
		},
		{
			name:            "modified cert pool",
			certPool:        x509.NewCertPool(),
			wantErrContains: "signed by unknown authority",
		},
		{
			name:            "modified dns name",
			dnsName:         bytes.NewBuffer([]byte("foobar")),
			wantErrContains: "not foobar",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			sar, err := tcl.AuthorizeSession(ctx, "ttcp_1234567890")
			require.NoError(err)
			require.NotNil(sar)

			sessAuth, err := sar.GetSessionAuthorization()
			require.NoError(err)
			sessAuthzData, err := sessAuth.GetSessionAuthorizationData()
			require.NoError(err)
			require.LessOrEqual(1, len(sessAuthzData.WorkerInfo))
			tlsConf := apiproxy.TestClientTlsConfig(t, sessAuth.AuthorizationToken, apiproxy.WithWorkerHost(sessAuth.SessionId))

			certPool := tc.certPool
			if certPool == nil {
				parsedCert, err := x509.ParseCertificate(sessAuthzData.Certificate)
				require.NoError(err)
				certPool = x509.NewCertPool()
				certPool.AddCert(parsedCert)
			}

			dnsName := sessAuth.SessionId
			if tc.dnsName != nil {
				dnsName = tc.dnsName.String()
			}

			verifyOpts := x509.VerifyOptions{
				DNSName: dnsName,
				Roots:   certPool,
				KeyUsages: []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageServerAuth,
				},
			}
			tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
				// Go will not run this without at least one peer certificate, but
				// doesn't hurt to check
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no peer certificates provided")
				}
				_, err := cs.PeerCertificates[0].Verify(verifyOpts)
				return err
			}

			transport := cleanhttp.DefaultTransport()
			transport.DisableKeepAlives = false
			// This isn't/shouldn't used anyways really because the connection is
			// hijacked, just setting for completeness
			transport.IdleConnTimeout = 0
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &tls.Dialer{Config: tlsConf}
				return dialer.DialContext(ctx, network, addr)
			}

			conn, _, err := websocket.Dial(
				ctx,
				fmt.Sprintf("ws://%s/v1/proxy", sessAuthzData.WorkerInfo[0].Address),
				&websocket.DialOptions{
					HTTPClient: &http.Client{
						Transport: transport,
					},
					Subprotocols: []string{globals.TcpProxyV1},
				},
			)
			if conn != nil {
				defer conn.Close(websocket.StatusNormalClosure, "done")
			}
			switch tc.wantErrContains != "" {
			case true:
				require.Error(err)
				require.Contains(err.Error(), tc.wantErrContains)
			default:
				require.NoError(err)
			}
		})
	}
}

func TestCustomX509Verification_Server(t *testing.T) {
	t.Skip("These tests are currently not working and will need further investigation")

	ec := event.TestEventerConfig(t, "TestCustomX509Verification_Server", event.TestWithObservationSink(t), event.TestWithSysSink(t))
	testLock := &sync.Mutex{}
	logger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
		Level: hclog.Trace,
	})
	require.NoError(t, event.InitSysEventer(logger, testLock, "use-TestCustomX509Verification_Server", event.WithEventerConfig(&ec.EventerConfig)))
	t.Cleanup(func() { event.TestResetSystEventer(t) })
	t.Cleanup(func() {
		all, err := io.ReadAll(ec.AllEvents)
		require.NoError(t, err)
		t.Log(string(all))
	})

	t.Run("bad cert pool", testCustomX509Verification_Server(ec, x509.NewCertPool(), "", "bad certificate"))
	t.Run("bad dns name", testCustomX509Verification_Server(ec, nil, "foobar", "bad certificate"))
}

func testCustomX509Verification_Server(ec event.TestConfig, certPool *x509.CertPool, dnsName, wantErrContains string) func(t *testing.T) {
	return func(t *testing.T) {
		req := require.New(t)
		ctx := context.Background()
		// This prevents us from running tests in parallel.
		server.TestUseCommunityFilterWorkersFn(t)

		conf, err := config.DevController()
		conf.Eventing = &ec.EventerConfig
		req.NoError(err)
		c1 := controller.NewTestController(t, &controller.TestControllerOpts{
			Config:                 conf,
			InitialResourcesSuffix: "1234567890",
		})

		conf, err = config.DevWorker()
		conf.Eventing = &ec.EventerConfig
		req.NoError(err)
		w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
			WorkerAuthKms:     c1.Config().WorkerAuthKms,
			InitialUpstreams:  c1.ClusterAddrs(),
			WorkerRPCInterval: time.Second,
		})
		w1.Worker().TestOverrideX509VerifyCertPool = certPool
		w1.Worker().TestOverrideX509VerifyDnsName = dnsName

		// Give time for it to connect
		helper.ExpectWorkers(t, c1, w1)

		// Connect target
		client := c1.Client()
		client.SetToken(c1.Token().Token)
		tcl := targets.NewClient(client)
		tgt, err := tcl.Read(ctx, "ttcp_1234567890")
		req.NoError(err)
		req.NotNil(tgt)

		// Create test server, update default port on target
		ts := helper.NewTestTcpServer(t)
		require.NotNil(t, ts)
		t.Cleanup(ts.Close)
		tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(-1))
		req.NoError(err)
		req.NotNil(tgt)

		sar, err := tcl.AuthorizeSession(ctx, "ttcp_1234567890")
		req.NoError(err)
		req.NotNil(sar)
		sessAuth, err := sar.GetSessionAuthorization()
		req.NoError(err)
		sessAuthzData, err := sessAuth.GetSessionAuthorizationData()
		req.NoError(err)
		req.LessOrEqual(1, len(sessAuthzData.WorkerInfo))
		tlsConf := apiproxy.TestClientTlsConfig(t, sessAuth.AuthorizationToken, apiproxy.WithWorkerHost(sessAuth.SessionId))

		transport := cleanhttp.DefaultTransport()
		transport.DisableKeepAlives = false
		// This isn't/shouldn't used anyways really because the connection is
		// hijacked, just setting for completeness
		transport.IdleConnTimeout = 0
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &tls.Dialer{Config: tlsConf}
			return dialer.DialContext(ctx, network, addr)
		}

		conn, _, err := websocket.Dial(
			ctx,
			fmt.Sprintf("wss://%s/v1/proxy", sessAuthzData.WorkerInfo[0].Address),
			&websocket.DialOptions{
				HTTPClient: &http.Client{
					Transport: transport,
				},
				Subprotocols: []string{globals.TcpProxyV1},
			},
		)
		if conn != nil {
			defer conn.Close(websocket.StatusNormalClosure, "done")
		}
		switch wantErrContains != "" {
		case true:
			req.Error(err)
			req.Contains(err.Error(), wantErrContains)
		default:
			req.NoError(err)
		}
	}
}
