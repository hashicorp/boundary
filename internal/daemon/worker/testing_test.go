package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
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
	manager := session.NewManager(mockSessionClient)
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
			require.Equal(tt.wrapper, tw.Config().WorkerAuthStorageKms)
		})
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
