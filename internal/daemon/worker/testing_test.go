// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

func TestTestWorkerLookupSession(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	mockSessionClient := pbs.NewMockSessionServiceClient()
	manager, err := session.NewManager(mockSessionClient)
	require.NoError(err)
	mockSessionClient.LookupSessionFn = func(_ context.Context, request *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
		cert, _, _ := createTestCert(t)
		return &pbs.LookupSessionResponse{
			Authorization: &targets.SessionAuthorizationData{
				SessionId:   request.GetSessionId(),
				Certificate: cert,
			},
			Version:    1,
			TofuToken:  "tofu",
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
		}, nil
	}
	s, err := manager.LoadLocalSession(ctx, "foo", "worker id")
	require.NoError(err)
	mockSessionClient.ActivateSessionFn = func(_ context.Context, _ *pbs.ActivateSessionRequest) (*pbs.ActivateSessionResponse, error) {
		return &pbs.ActivateSessionResponse{Status: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE}, nil
	}
	require.NoError(s.RequestActivate(ctx, "tofu"))

	mockSessionClient.AuthorizeConnectionFn = func(_ context.Context, req *pbs.AuthorizeConnectionRequest) (*pbs.AuthorizeConnectionResponse, error) {
		return &pbs.AuthorizeConnectionResponse{
			ConnectionId:    "one",
			Status:          pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
			ConnectionsLeft: -1,
		}, nil
	}
	_, cancelFn := context.WithCancel(context.Background())
	_, _, err = s.RequestAuthorizeConnection(ctx, "worker id", cancelFn)
	require.NoError(err)
	require.NoError(s.ApplyLocalConnectionStatus("one", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED))

	tw := new(TestWorker)
	tw.w = &Worker{
		sessionManager: manager,
	}

	closeTime := s.GetLocalConnections()["one"].CloseTime
	assert.NotZero(t, closeTime)
	expected := TestSessionInfo{
		Id:     "foo",
		Status: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
		Connections: map[string]TestConnectionInfo{
			"one": {
				Id:        "one",
				Status:    pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
				CloseTime: closeTime,
			},
		},
	}

	actual, ok := tw.LookupSession("foo")
	require.True(ok)
	require.Equal(expected, actual)
}

func TestTestWorkerLookupSessionMissing(t *testing.T) {
	require := require.New(t)
	tw := NewTestWorker(t, nil)
	actual, ok := tw.LookupSession("missing")
	require.False(ok)
	require.Equal(TestSessionInfo{}, actual)
}

func TestTestWorker_WorkerAuthStorageKms(t *testing.T) {
	tests := []struct {
		name    string
		wrapper wrapping.Wrapper
	}{
		{
			name:    "Nil Wrapper",
			wrapper: nil,
		},
		{
			name:    "Valid Wrapper",
			wrapper: db.TestWrapper(t),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			tw := NewTestWorker(t, &TestWorkerOpts{
				WorkerAuthStorageKms: tt.wrapper,
			})
			if tt.wrapper == nil {
				// DevWorker config will create one
				require.NotNil(tw.Config().WorkerAuthStorageKms)
			} else {
				require.Equal(tt.wrapper, tw.Config().WorkerAuthStorageKms)
			}
		})
	}
}

func TestNewAuthorizedPkiTestWorker(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})
	conf, err := config.DevController()
	require.NoError(t, err)
	c := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("controller"),
	})
	tw, id := NewAuthorizedPkiTestWorker(t, c.ServersRepo(), "test", c.ClusterAddrs())
	assert.NotNil(t, tw)
	assert.NotEmpty(t, id)

	w, err := c.ServersRepo().LookupWorker(context.Background(), id)
	assert.NoError(t, err)
	assert.NotNil(t, w)
	assert.Equal(t, "pki", w.GetType())
	assert.Equal(t, "test", w.GetName())
}

func TestNewTestMultihopWorkers(t *testing.T) {
	ctx := context.Background()
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})
	conf, err := config.DevController()
	require.NoError(t, err)
	c := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("controller"),
	})
	pkiTags := map[string][]string{"connected": {"directly"}}
	childPkiTags := map[string][]string{"connected": {"multihop"}}
	childKmsTags := map[string][]string{"connected": {"multihop"}}

	enableAuthDebugging := new(atomic.Bool)
	enableAuthDebugging.Store(true)
	kmsWorker, pkiWorker, childPkiWorker, childKmsWorker := NewTestMultihopWorkers(t, logger, c.Context(), c.ClusterAddrs(),
		c.Config().WorkerAuthKms, c.Controller().ServersRepoFn, pkiTags, childPkiTags, childKmsTags, enableAuthDebugging)

	srvRepo, err := c.Controller().ServersRepoFn()
	require.NoError(t, err)
	workers, err := srvRepo.ListWorkers(ctx, []string{"global"})
	assert.Len(t, workers, 4)
	require.NoError(t, err)
	var kmsW, pkiW, childPkiW, childKmsW *server.Worker
	for _, w := range workers {
		switch w.GetAddress() {
		case kmsWorker.ProxyAddrs()[0]:
			kmsW = w
		case pkiWorker.ProxyAddrs()[0]:
			pkiW = w
		case childPkiWorker.ProxyAddrs()[0]:
			childPkiW = w
		case childKmsWorker.ProxyAddrs()[0]:
			childKmsW = w
		}
	}
	require.NotNil(t, kmsW)
	require.NotNil(t, pkiW)
	require.NotNil(t, childPkiW)
	require.NotNil(t, childKmsW)

	assert.NotZero(t, kmsW.GetLastStatusTime())
	assert.NotZero(t, pkiW.GetLastStatusTime())
	assert.NotZero(t, childPkiW.GetLastStatusTime())
	assert.NotZero(t, childKmsW.GetLastStatusTime())

	assert.Equal(t, pkiTags, pkiW.GetConfigTags())
	assert.Equal(t, childPkiTags, childPkiW.GetConfigTags())
	assert.Equal(t, childKmsTags, childKmsW.GetConfigTags())

	require.NoError(t, c.WaitForNextWorkerStatusUpdate(kmsWorker.Name()))
	require.NoError(t, c.WaitForNextWorkerStatusUpdate(pkiWorker.Name()))
	require.NoError(t, c.WaitForNextWorkerStatusUpdate(childPkiWorker.Name()))
	require.NoError(t, c.WaitForNextWorkerStatusUpdate(childKmsWorker.Name()))
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
