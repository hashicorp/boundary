package session

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestConnection creates a test connection for the sessionId in the repository.
func TestConnection(t testing.TB, conn *db.DB, sessionId, clientTcpAddr string, clientTcpPort uint32, endpointTcpAddr string, endpointTcpPort uint32, userClientIp string) *Connection {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	c, err := NewConnection(sessionId, clientTcpAddr, clientTcpPort, endpointTcpAddr, endpointTcpPort, userClientIp)
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
func TestConnectionState(t testing.TB, conn *db.DB, connectionId string, state ConnectionStatus) *ConnectionState {
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
func TestState(t testing.TB, conn *db.DB, sessionId string, state Status) *State {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	s, err := NewState(sessionId, state)
	require.NoError(err)
	err = rw.Create(context.Background(), s)
	require.NoError(err)
	return s
}

// TestSession creates a test session composed of c in the repository. Options
// are passed into New, and withServerId is handled locally.
func TestSession(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, c ComposedOf, opt ...Option) *Session {
	t.Helper()
	ctx := context.Background()
	opts := getOpts(opt...)
	require := require.New(t)
	if c.ExpirationTime == nil {
		future := timestamppb.New(time.Now().Add(time.Hour))
		c.ExpirationTime = &timestamp.Timestamp{Timestamp: future}
	}
	rw := db.New(conn)
	s, err := New(c, opt...)
	require.NoError(err)
	id, err := newId()
	require.NoError(err)
	s.PublicId = id
	_, certBytes, err := newCert(ctx, wrapper, c.UserId, id, []string{"127.0.0.1", "localhost"}, c.ExpirationTime.Timestamp.AsTime())
	require.NoError(err)
	s.Certificate = certBytes
	s.ServerId = opts.withServerId

	if len(s.TofuToken) != 0 {
		err = s.encrypt(ctx, wrapper)
	}
	require.NoError(err)
	err = rw.Create(ctx, s, opts.withDbOpts...)
	require.NoError(err)

	for _, cred := range s.DynamicCredentials {
		cred.SessionId = s.PublicId
		err := rw.Create(ctx, cred)
		require.NoError(err)
	}

	ss, err := fetchStates(ctx, rw, s.PublicId, append(opts.withDbOpts, db.WithOrder("start_time desc"))...)
	require.NoError(err)
	s.States = ss

	return s
}

// TestDefaultSession creates a test session in the repository using defaults.
func TestDefaultSession(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository, opt ...Option) *Session {
	t.Helper()
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
	future := timestamppb.New(time.Now().Add(time.Hour))
	exp := &timestamp.Timestamp{Timestamp: future}
	return TestSession(t, conn, wrapper, composedOf, append(opt, WithExpirationTime(exp))...)
}

// TestSessionParams returns an initialized ComposedOf which can be used to
// create a session in the repository.
func TestSessionParams(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository) ComposedOf {
	t.Helper()
	ctx := context.Background()

	require := require.New(t)
	rw := db.New(conn)
	org, proj := iam.TestScopes(t, iamRepo)

	cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
	hosts := static.TestHosts(t, conn, cats[0].PublicId, 1)
	sets := static.TestSets(t, conn, cats[0].PublicId, 1)
	_ = static.TestSetMembers(t, conn, sets[0].PublicId, hosts)

	tcpTarget := tcp.TestTarget(ctx, t, conn, proj.PublicId, "test target")

	kms := kms.TestKms(t, conn, wrapper)
	targetRepo, err := target.NewRepository(rw, rw, kms)
	require.NoError(err)
	_, _, _, err = targetRepo.AddTargetHostSources(ctx, tcpTarget.GetPublicId(), tcpTarget.GetVersion(), []string{sets[0].PublicId})
	require.NoError(err)

	authMethod := password.TestAuthMethods(t, conn, org.PublicId, 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "name1")
	user := iam.TestUser(t, iamRepo, org.PublicId, iam.WithAccountIds(acct.PublicId))

	authTokenRepo, err := authtoken.NewRepository(rw, rw, kms)
	require.NoError(err)
	at, err := authTokenRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
	require.NoError(err)

	expTime := timestamppb.Now()
	expTime.Seconds += int64(tcpTarget.GetSessionMaxSeconds())
	return ComposedOf{
		UserId:          user.PublicId,
		HostId:          hosts[0].PublicId,
		TargetId:        tcpTarget.GetPublicId(),
		HostSetId:       sets[0].PublicId,
		AuthTokenId:     at.PublicId,
		ScopeId:         tcpTarget.GetScopeId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ExpirationTime:  &timestamp.Timestamp{Timestamp: expTime},
		ConnectionLimit: tcpTarget.GetSessionConnectionLimit(),
	}
}

// TestTofu will create a test "trust on first use" token
func TestTofu(t testing.TB) []byte {
	t.Helper()
	require := require.New(t)
	tofu, err := base62.Random(20)
	require.NoError(err)
	return []byte(tofu)
}

// TestWorker inserts a worker into the db to satisfy foreign key constraints.
// Supports the WithServerId option.
func TestWorker(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, opt ...Option) *servers.Server {
	t.Helper()
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	opts := getOpts(opt...)
	id := opts.withServerId
	if id == "" {
		id, err = uuid.GenerateUUID()
		require.NoError(t, err)
		id = "test-session-worker-" + id
	}
	worker := &servers.Server{
		PrivateId:   id,
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
	return newCert(context.Background(), wrapper, userId, jobId, []string{"127.0.0.1", "localhost"}, time.Now().Add(5*time.Minute))
}
