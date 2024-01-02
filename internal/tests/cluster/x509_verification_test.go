// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	tg "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

func TestCustomX509Verification_Client(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	ec := event.TestEventerConfig(t, "TestWorkerReplay", event.TestWithObservationSink(t), event.TestWithSysSink(t))
	testLock := &sync.Mutex{}
	tg.SetupSuiteTargetFilters(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	req.NoError(event.InitSysEventer(logger, testLock, "use-TestCustomX509Verification", event.WithEventerConfig(&ec.EventerConfig)))

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
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w1"),
	})

	// Give time for it to connect
	time.Sleep(10 * time.Second)

	err = w1.Worker().WaitForNextSuccessfulStatusUpdate()
	req.NoError(err)

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
			sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890")

			certPool := tc.certPool
			if certPool == nil {
				parsedCert, err := x509.ParseCertificate(sess.SessionAuthzData.Certificate)
				require.NoError(err)
				certPool = x509.NewCertPool()
				certPool.AddCert(parsedCert)
			}

			dnsName := sess.SessionId
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
			sess.Transport.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
				// Go will not run this without at least one peer certificate, but
				// doesn't hurt to check
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no peer certificates provided")
				}
				_, err := cs.PeerCertificates[0].Verify(verifyOpts)
				return err
			}
			conn, _, err := websocket.Dial(
				ctx,
				fmt.Sprintf("wss://%s/v1/proxy", sess.WorkerAddr),
				&websocket.DialOptions{
					HTTPClient: &http.Client{
						Transport: sess.Transport,
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
	ec := event.TestEventerConfig(t, "TestCustomX509Verification_Server", event.TestWithObservationSink(t), event.TestWithSysSink(t))
	testLock := &sync.Mutex{}
	logger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(t, event.InitSysEventer(logger, testLock, "use-TestCustomX509Verification_Server", event.WithEventerConfig(&ec.EventerConfig)))

	t.Run("bad cert pool", testCustomX509Verification_Server(ec, x509.NewCertPool(), "", "bad certificate"))
	t.Run("bad dns name", testCustomX509Verification_Server(ec, nil, "foobar", "bad certificate"))
}

func testCustomX509Verification_Server(ec event.TestConfig, certPool *x509.CertPool, dnsName, wantErrContains string) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		req := require.New(t)
		ctx := context.Background()
		tg.SetupSuiteTargetFilters(t)

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
			WorkerAuthKms:    c1.Config().WorkerAuthKms,
			InitialUpstreams: c1.ClusterAddrs(),
		})
		w1.Worker().TestOverrideX509VerifyCertPool = certPool
		w1.Worker().TestOverrideX509VerifyDnsName = dnsName

		// Give time for it to connect
		time.Sleep(10 * time.Second)

		err = w1.Worker().WaitForNextSuccessfulStatusUpdate()
		req.NoError(err)

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

		sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890")

		conn, _, err := websocket.Dial(
			ctx,
			fmt.Sprintf("wss://%s/v1/proxy", sess.WorkerAddr),
			&websocket.DialOptions{
				HTTPClient: &http.Client{
					Transport: sess.Transport,
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
