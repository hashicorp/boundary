package session

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/target"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestConnection creates a test connection for the sessionId in the repository.
func TestConnection(t *testing.T, conn *gorm.DB, sessionId, clientTcpAddr string, clientTcpPort uint32, endpointTcpAddr string, endpointTcpPort uint32) *Connection {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	c, err := NewConnection(sessionId, clientTcpAddr, clientTcpPort, endpointTcpAddr, endpointTcpPort)
	require.NoError(err)
	id, err := newConnectionId()
	require.NoError(err)
	c.PublicId = id
	err = rw.Create(context.Background(), c)
	require.NoError(err)

	connectedState, err := NewConnectionState(c.PublicId, StatusConnected)
	require.NoError(err)
	err = rw.Create(context.Background(), connectedState)
	require.NoError(err)
	return c
}

// TestConnectionState creates a test connection state for the connectionId in the repository.
func TestConnectionState(t *testing.T, conn *gorm.DB, connectionId string, state ConnectionStatus) *ConnectionState {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	s, err := NewConnectionState(connectionId, state)
	require.NoError(err)
	err = rw.Create(context.Background(), s)
	require.NoError(err)
	return s
}

// TestState creates a test state for the sessionId in the repository.
func TestState(t *testing.T, conn *gorm.DB, sessionId string, state Status) *State {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	s, err := NewState(sessionId, state)
	require.NoError(err)
	err = rw.Create(context.Background(), s)
	require.NoError(err)
	return s
}

// TestSession creates a test session composed of c in the repository.
func TestSession(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, c ComposedOf, opt ...Option) *Session {
	t.Helper()
	require := require.New(t)
	if c.ExpirationTime == nil {
		future, err := ptypes.TimestampProto(time.Now().Add(time.Hour))
		require.NoError(err)
		c.ExpirationTime = &timestamp.Timestamp{Timestamp: future}
	}
	rw := db.New(conn)
	s, err := New(c, opt...)
	require.NoError(err)
	id, err := newId()
	require.NoError(err)
	s.PublicId = id
	_, certBytes, err := newCert(wrapper, c.UserId, id, c.ExpirationTime.Timestamp.AsTime())
	require.NoError(err)
	s.Certificate = certBytes

	if len(s.TofuToken) != 0 {
		err = s.encrypt(context.Background(), wrapper)
	}
	require.NoError(err)
	err = rw.Create(context.Background(), s)
	require.NoError(err)
	ss, err := fetchStates(context.Background(), rw, s.PublicId, db.WithOrder("start_time desc"))
	require.NoError(err)
	s.States = ss

	return s
}

// TestDefaultSession creates a test session in the repository using defaults.
func TestDefaultSession(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository, opt ...Option) *Session {
	t.Helper()
	require := require.New(t)
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
	future, err := ptypes.TimestampProto(time.Now().Add(time.Hour))
	require.NoError(err)
	exp := &timestamp.Timestamp{Timestamp: future}
	return TestSession(t, conn, wrapper, composedOf, WithExpirationTime(exp))
}

// TestSessionParams returns an initialized ComposedOf which can be used to
// create a session in the repository.
func TestSessionParams(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository) ComposedOf {
	t.Helper()
	ctx := context.Background()

	require := require.New(t)
	rw := db.New(conn)
	org, proj := iam.TestScopes(t, iamRepo)

	cats := static.TestCatalogs(t, conn, proj.PublicId, 1)

	hosts := static.TestHosts(t, conn, cats[0].PublicId, 1)

	sets := static.TestSets(t, conn, cats[0].PublicId, 1)
	_ = static.TestSetMembers(t, conn, sets[0].PublicId, hosts)

	tcpTarget := target.TestTcpTarget(t, conn, proj.PublicId, "test target")

	kms := kms.TestKms(t, conn, wrapper)
	targetRepo, err := target.NewRepository(rw, rw, kms)
	require.NoError(err)
	_, _, err = targetRepo.AddTargetHostSets(ctx, tcpTarget.GetPublicId(), tcpTarget.GetVersion(), []string{sets[0].PublicId})
	require.NoError(err)

	authMethod := password.TestAuthMethods(t, conn, org.PublicId, 1)[0]
	acct := password.TestAccounts(t, conn, authMethod.GetPublicId(), 1)[0]
	user, err := iamRepo.LookupUserWithLogin(ctx, acct.GetPublicId(), iam.WithAutoVivify(true))
	require.NoError(err)

	authTokenRepo, err := authtoken.NewRepository(rw, rw, kms)
	require.NoError(err)
	at, err := authTokenRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
	require.NoError(err)

	expTime := timestamppb.Now()
	expTime.Seconds += int64(tcpTarget.GetSessionMaxSeconds())
	return ComposedOf{
		UserId:          user.PublicId,
		HostId:          hosts[0].PublicId,
		TargetId:        tcpTarget.PublicId,
		HostSetId:       sets[0].PublicId,
		AuthTokenId:     at.PublicId,
		ScopeId:         tcpTarget.ScopeId,
		Endpoint:        "tcp://127.0.0.1:22",
		ExpirationTime:  &timestamp.Timestamp{Timestamp: expTime},
		ConnectionLimit: tcpTarget.GetSessionConnectionLimit(),
	}
}

// TestTofu will create a test "trust on first use" token
func TestTofu(t *testing.T) []byte {
	t.Helper()
	require := require.New(t)
	tofu, err := base62.Random(20)
	require.NoError(err)
	return []byte(tofu)
}

func TestWorker(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper) *servers.Server {
	t.Helper()
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	worker := &servers.Server{
		PrivateId:   "test-session-worker-" + id,
		Type:        servers.ServerTypeWorker.String(),
		Description: "Test Session Worker",
		Address:     "127.0.0.1",
	}
	_, _, err = serversRepo.UpsertServer(context.Background(), worker)
	require.NoError(t, err)
	return worker
}

// TestCert is a temporary test func that intentionally doesn't take testing.T
// as a parameter.  It's currently used in controller.jobTestingHandler() and
// should be deprecated once that function is refactored to use sessions properly.
func TestCert(wrapper wrapping.Wrapper, userId, jobId string) (ed25519.PrivateKey, []byte, error) {
	return newCert(wrapper, userId, jobId, time.Now().Add(5*time.Minute))
}
