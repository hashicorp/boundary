// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestConnection creates a test connection for the sessionId in the repository.
func TestConnection(t testing.TB, conn *db.DB, sessionId, clientTcpAddr string, clientTcpPort uint32, endpointTcpAddr string, endpointTcpPort uint32, userClientIp string) *Connection {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)
	c, err := NewConnection(ctx, sessionId, clientTcpAddr, clientTcpPort, endpointTcpAddr, endpointTcpPort, userClientIp)
	require.NoError(err)
	id, err := newConnectionId(ctx)
	require.NoError(err)
	c.PublicId = id
	err = rw.Create(ctx, c)
	require.NoError(err)

	connectedState, err := NewConnectionState(ctx, c.PublicId, StatusConnected)
	require.NoError(err)
	err = rw.Create(ctx, connectedState)
	require.NoError(err)
	return c
}

// TestConnectionState creates a test connection state for the connectionId in the repository.
func TestConnectionState(t testing.TB, conn *db.DB, connectionId string, state ConnectionStatus) *ConnectionState {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	rw := db.New(conn)
	s, err := NewConnectionState(ctx, connectionId, state)
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
	s, err := NewState(context.Background(), sessionId, state)
	require.NoError(err)
	err = rw.Create(context.Background(), s)
	require.NoError(err)
	return s
}

// TestSessionHostSetHost creates a test session to host set host association for the sessionId in the repository.
func TestSessionHostSetHost(t testing.TB, conn *db.DB, sessionId, hostSetId, hostId string) {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	hs, err := NewSessionHostSetHost(context.Background(), sessionId, hostSetId, hostId)
	require.NoError(err)
	err = rw.Create(context.Background(), hs)
	require.NoError(err)
}

// TestSessionTargetAddress creates a test session to target address association for the sessionId in the repository.
func TestSessionTargetAddress(t testing.TB, conn *db.DB, sessionId, targetId string) {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	ta, err := NewSessionTargetAddress(context.Background(), sessionId, targetId)
	require.NoError(err)
	err = rw.Create(context.Background(), ta)
	require.NoError(err)
}

// TestSession creates a test session composed of c in the repository. Options
// are passed into New, and withServerId is handled locally.
func TestSession(t testing.TB, conn *db.DB, rootWrapper wrapping.Wrapper, c ComposedOf, opt ...Option) *Session {
	t.Helper()
	ctx := context.Background()
	opts := getOpts(opt...)
	require := require.New(t)
	if c.ExpirationTime == nil {
		future := timestamppb.New(time.Now().Add(time.Hour))
		c.ExpirationTime = &timestamp.Timestamp{Timestamp: future}
	}
	rw := db.New(conn)
	s, err := New(ctx, c, opt...)
	require.NoError(err)
	id, err := newId(ctx)
	require.NoError(err)
	s.PublicId = id
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	wrapper, err := kmsCache.GetWrapper(ctx, c.ProjectId, kms.KeyPurposeSessions)
	require.NoError(err)
	privateKey, certBytes, err := newCert(ctx, id, []string{"127.0.0.1", "localhost"}, c.ExpirationTime.Timestamp.AsTime(), rand.Reader)
	require.NoError(err)
	s.Certificate = certBytes
	s.CertificatePrivateKey = privateKey
	err = s.encrypt(ctx, wrapper)
	require.NoError(err)
	err = rw.Create(ctx, s, opts.withDbOpts...)
	if e, ok := err.(*errors.Err); err != nil && ok && e.Code == errors.NotUnique {
		// Sometimes we can get unique constraint errors when creating a session,
		// if that happens, just retry.
		err = rw.Create(ctx, s, opts.withDbOpts...)
	}
	require.NoError(err)

	for _, cred := range s.DynamicCredentials {
		cred.SessionId = s.PublicId
		err := rw.Create(ctx, cred)
		require.NoError(err)
	}

	for _, cred := range s.StaticCredentials {
		cred.SessionId = s.PublicId
		err := rw.Create(ctx, cred)
		require.NoError(err)
	}

	if s.HostId != "" && s.HostSetId != "" {
		TestSessionHostSetHost(t, conn, s.PublicId, s.HostSetId, s.HostId)
	} else if s.Endpoint != "" {
		TestSessionTargetAddress(t, conn, s.PublicId, s.TargetId)
	}

	if s.ProtocolWorkerId != "" {
		p, err := NewSessionWorkerProtocol(ctx, s.PublicId, s.ProtocolWorkerId)
		require.NoError(err)
		err = rw.Create(ctx, p)
		require.NoError(err)
	}

	ss, err := fetchStates(ctx, rw, s.PublicId, append(opts.withDbOpts, db.WithOrder("start_time desc"))...)
	require.NoError(err)
	s.States = ss

	return s
}

func TestSessionWithTargetAddress(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository, opt ...Option) *Session {
	t.Helper()
	composedOf := TestSessionTargetAddressParams(t, conn, wrapper, iamRepo)
	future := timestamppb.New(time.Now().Add(time.Hour))
	exp := &timestamp.Timestamp{Timestamp: future}
	return TestSession(t, conn, wrapper, composedOf, append(opt, WithExpirationTime(exp))...)
}

func TestSessionTargetAddressParams(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository) ComposedOf {
	t.Helper()
	ctx := context.Background()

	require := require.New(t)
	rw := db.New(conn)
	org, proj := iam.TestScopes(t, iamRepo)

	tcpTarget := tcp.TestTarget(ctx, t, conn, proj.PublicId, "test target")
	target.TestTargetAddress(t, conn, tcpTarget.GetPublicId(), "tcp://127.0.0.1:22")

	kms := kms.TestKms(t, conn, wrapper)
	authMethod := password.TestAuthMethods(t, conn, org.PublicId, 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "name1")
	user := iam.TestUser(t, iamRepo, org.PublicId, iam.WithAccountIds(acct.PublicId))

	authTokenRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	at, err := authTokenRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
	require.NoError(err)

	expTime := timestamppb.Now()
	expTime.Seconds += int64(tcpTarget.GetSessionMaxSeconds())
	return ComposedOf{
		UserId:          user.PublicId,
		TargetId:        tcpTarget.GetPublicId(),
		AuthTokenId:     at.PublicId,
		ProjectId:       tcpTarget.GetProjectId(),
		Endpoint:        "tcp://127.0.0.1:22",
		ExpirationTime:  &timestamp.Timestamp{Timestamp: expTime},
		ConnectionLimit: tcpTarget.GetSessionConnectionLimit(),
	}
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
	targetRepo, err := target.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	_, err = targetRepo.AddTargetHostSources(ctx, tcpTarget.GetPublicId(), tcpTarget.GetVersion(), []string{sets[0].PublicId})
	require.NoError(err)

	authMethod := password.TestAuthMethods(t, conn, org.PublicId, 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "name1")
	user := iam.TestUser(t, iamRepo, org.PublicId, iam.WithAccountIds(acct.PublicId))

	authTokenRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
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
		ProjectId:       tcpTarget.GetProjectId(),
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

// TestCert is a temporary test func that intentionally doesn't take testing.T
// as a parameter.  It's currently used in controller.jobTestingHandler() and
// should be deprecated once that function is refactored to use sessions properly.
func TestCert(jobId string) (ed25519.PrivateKey, []byte, error) {
	return newCert(context.Background(), jobId, []string{"127.0.0.1", "localhost"}, time.Now().Add(5*time.Minute), rand.Reader)
}
