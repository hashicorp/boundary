// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/authtoken"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/servers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	intglobals "github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/testdata"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

type fakeControllerExtension struct {
	reader db.Reader
	writer db.Writer
}

var _ intglobals.ControllerExtension = (*fakeControllerExtension)(nil)

func (f *fakeControllerExtension) Start(_ context.Context) error { return nil }

func TestLookupSession(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opts...)
	}
	connectionRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	worker1 := server.TestKmsWorker(t, conn, wrapper, server.WithName("testworker"))
	sessWithWorkerFilter := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:       uId,
		HostId:       h.GetPublicId(),
		TargetId:     tar.GetPublicId(),
		HostSetId:    hs.GetPublicId(),
		AuthTokenId:  at.GetPublicId(),
		ProjectId:    prj.GetPublicId(),
		Endpoint:     "tcp://127.0.0.1:22",
		WorkerFilter: fmt.Sprintf("%q matches %q", "/name", worker1.GetName()),
	})

	sessWithCreds := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	repo, err := sessionRepoFn()
	require.NoError(t, err)

	creds := []*pbs.Credential{
		{
			Credential: &pbs.Credential_UsernamePassword{
				UsernamePassword: &pbs.UsernamePassword{
					Username: "username",
					Password: "password",
				},
			},
		},
		{
			Credential: &pbs.Credential_SshPrivateKey{
				SshPrivateKey: &pbs.SshPrivateKey{
					Username:   "another-username",
					PrivateKey: credstatic.TestLargeSshPrivateKeyPem,
				},
			},
		},
		{
			Credential: &pbs.Credential_SshPrivateKey{
				SshPrivateKey: &pbs.SshPrivateKey{
					Username:   "another-username",
					PrivateKey: string(testdata.PEMBytes["ed25519"]),
				},
			},
		},
		{
			Credential: &pbs.Credential_SshPrivateKey{
				SshPrivateKey: &pbs.SshPrivateKey{
					Username:             "another-username",
					PrivateKey:           string(testdata.PEMEncryptedKeys[0].PEMBytes),
					PrivateKeyPassphrase: testdata.PEMEncryptedKeys[0].EncryptionKey,
				},
			},
		},
	}

	workerCreds := make([]session.Credential, 0, len(creds))
	for _, c := range creds {
		data, err := proto.Marshal(c)
		require.NoError(t, err)
		workerCreds = append(workerCreds, data)
	}
	err = repo.AddSessionCredentials(ctx, sessWithCreds.ProjectId, sessWithCreds.GetPublicId(), workerCreds)
	require.NoError(t, err)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
	require.NotNil(t, s)

	oldFn := connectionRouteFn
	connectionRouteFn = singleHopConnectionRoute
	t.Cleanup(func() {
		connectionRouteFn = oldFn
	})

	cases := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
		want       *pbs.LookupSessionResponse
		req        *pbs.LookupSessionRequest
	}{
		{
			name: "Invalid session id",
			req: &pbs.LookupSessionRequest{
				SessionId: "s_fakesession",
				WorkerId:  worker1.GetPublicId(),
			},
			wantErr:    true,
			wantErrMsg: "rpc error: code = PermissionDenied desc = Unknown session ID.",
		},
		{
			name: "no worker id",
			req: &pbs.LookupSessionRequest{
				SessionId: sessWithWorkerFilter.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "rpc error: code = InvalidArgument desc = Did not receive worker id when looking up session",
		},
		{
			name: "nonexistent worker id",
			req: &pbs.LookupSessionRequest{
				SessionId: sessWithWorkerFilter.PublicId,
				WorkerId:  "w_nonexistingworker",
			},
			wantErr:    true,
			wantErrMsg: "rpc error: code = Internal desc = Worker not found",
		},
		{
			name: "Valid",
			req: &pbs.LookupSessionRequest{
				SessionId: sess.PublicId,
				WorkerId:  worker1.GetPublicId(),
			},
			want: &pbs.LookupSessionResponse{
				Authorization: &targets.SessionAuthorizationData{
					SessionId:   sess.PublicId,
					Certificate: sess.Certificate,
					PrivateKey:  sess.CertificatePrivateKey,
				},
				ConnectionLimit: 1,
				ConnectionsLeft: 1,
				Version:         1,
				Endpoint:        sess.Endpoint,
				HostId:          sess.HostId,
				HostSetId:       sess.HostSetId,
				TargetId:        sess.TargetId,
				UserId:          sess.UserId,
				Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
			},
		},
		{
			name: "Valid with worker filter",
			req: &pbs.LookupSessionRequest{
				SessionId: sess.PublicId,
				WorkerId:  worker1.GetPublicId(),
			},
			want: &pbs.LookupSessionResponse{
				Authorization: &targets.SessionAuthorizationData{
					SessionId:   sess.PublicId,
					Certificate: sess.Certificate,
					PrivateKey:  sess.CertificatePrivateKey,
				},
				ConnectionLimit: 1,
				ConnectionsLeft: 1,
				Version:         1,
				Endpoint:        sess.Endpoint,
				HostId:          sess.HostId,
				HostSetId:       sess.HostSetId,
				TargetId:        sess.TargetId,
				UserId:          sess.UserId,
				Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
			},
		},
		{
			name: "Valid-with-worker-creds",
			req: &pbs.LookupSessionRequest{
				SessionId: sessWithCreds.PublicId,
				WorkerId:  worker1.GetPublicId(),
			},
			want: &pbs.LookupSessionResponse{
				Authorization: &targets.SessionAuthorizationData{
					SessionId:   sessWithCreds.PublicId,
					Certificate: sessWithCreds.Certificate,
					PrivateKey:  sessWithCreds.CertificatePrivateKey,
				},
				ConnectionLimit: 1,
				ConnectionsLeft: 1,
				Version:         1,
				Endpoint:        sessWithCreds.Endpoint,
				HostId:          sessWithCreds.HostId,
				HostSetId:       sessWithCreds.HostSetId,
				TargetId:        sessWithCreds.TargetId,
				UserId:          sessWithCreds.UserId,
				Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
				Credentials:     creds,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := s.LookupSession(ctx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Equal(tc.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Empty(
				cmp.Diff(
					tc.want,
					got,
					protocmp.Transform(),
					protocmp.IgnoreFields(&pbs.LookupSessionResponse{}, "expiration"),
				),
			)
		})
	}
}

func TestAuthorizeConnection(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	currentConnFn := connectionRouteFn
	t.Cleanup(func() {
		connectionRouteFn = currentConnFn
	})
	connectionRouteFn = singleHopConnectionRoute

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kmsCache, opts...)
	}
	connectionRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kmsCache)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	var workerKeyId string
	worker := server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&workerKeyId))
	serverRepo, err := serversRepoFn()
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	newTestSession := func(connLimit int32) *session.Session {
		return session.TestSession(t, conn, wrapper, session.ComposedOf{
			UserId:          uId,
			HostId:          h.GetPublicId(),
			TargetId:        tar.GetPublicId(),
			HostSetId:       hs.GetPublicId(),
			AuthTokenId:     at.GetPublicId(),
			ProjectId:       prj.GetPublicId(),
			Endpoint:        "tcp://127.0.0.1:22",
			ConnectionLimit: connLimit,
		})
	}

	repo, err := sessionRepoFn()
	require.NoError(t, err)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kmsCache, new(atomic.Int64), fce)
	require.NotNil(t, s)

	cases := []struct {
		name      string
		sessionId string
		want      *pbs.AuthorizeConnectionResponse
		wantErr   bool
	}{
		{
			name: "no-protocol-context",
			sessionId: func() string {
				sess := newTestSession(-1)

				tofuToken, err := base62.Random(20)
				require.NoError(t, err)
				_, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, []byte(tofuToken))
				require.NoError(t, err)

				return sess.GetPublicId()
			}(),
			want: &pbs.AuthorizeConnectionResponse{
				Status:          pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
				ConnectionsLeft: -1,
				Route:           []string{worker.PublicId},
			},
		},
		{
			name: "with-credentials",
			sessionId: func() string {
				sess := newTestSession(-1)

				data, err := proto.Marshal(&pbs.Credential{Credential: &pbs.Credential_UsernamePassword{
					UsernamePassword: &pbs.UsernamePassword{
						Username: "username",
						Password: "password",
					},
				}})
				require.NoError(t, err)
				err = repo.AddSessionCredentials(ctx, sess.ProjectId, sess.GetPublicId(), []session.Credential{data})
				require.NoError(t, err)

				tofuToken, err := base62.Random(20)
				require.NoError(t, err)
				_, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, []byte(tofuToken))
				require.NoError(t, err)

				return sess.GetPublicId()
			}(),
			want: &pbs.AuthorizeConnectionResponse{
				Status:          pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
				ConnectionsLeft: -1,
				Route:           []string{worker.PublicId},
			},
		},
		{
			name: "connection limit reached",
			sessionId: func() string {
				sess := newTestSession(1)
				tofuToken, err := base62.Random(20)
				require.NoError(t, err)
				_, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, []byte(tofuToken))
				require.NoError(t, err)

				// Take up the only connection limit.
				_, err = s.AuthorizeConnection(ctx,
					&pbs.AuthorizeConnectionRequest{
						SessionId: sess.GetPublicId(),
						WorkerId:  worker.GetPublicId(),
					})
				require.NoError(t, err)
				return sess.GetPublicId()
			}(),
			wantErr: true,
		},
		{
			name:      "non activated session",
			sessionId: newTestSession(-1).GetPublicId(),
			wantErr:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverRepo.UpsertWorkerStatus(ctx, worker, server.WithKeyId(workerKeyId))

			resp, err := s.AuthorizeConnection(ctx, &pbs.AuthorizeConnectionRequest{
				SessionId: tc.sessionId,
				WorkerId:  worker.GetPublicId(),
			})
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, resp.GetConnectionId())
			resp.ConnectionId = ""
			assert.Empty(t, cmp.Diff(resp, tc.want, protocmp.Transform()))
		})
	}
}

func TestCancelSession(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opts...)
	}
	connectionRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms)
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})
	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
	require.NotNil(t, s)
	cases := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
		want       *pbs.CancelSessionResponse
		req        *pbs.CancelSessionRequest
	}{
		{
			name: "Invalid session id",
			req: &pbs.CancelSessionRequest{
				SessionId: "s_fakesession",
			},
			wantErr:    true,
			wantErrMsg: "rpc error: code = PermissionDenied desc = Unknown session ID.",
		},
		{
			name: "Valid",
			req: &pbs.CancelSessionRequest{
				SessionId: sess.PublicId,
			},
			want: &pbs.CancelSessionResponse{
				Status: pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := s.CancelSession(ctx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Equal(tc.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Empty(
				cmp.Diff(
					tc.want,
					got,
					protocmp.Transform(),
				),
			)
		})
	}
}

// This test creates workers of both kms and pki type and verifies that the only
// returned workers are those that are alive with the expected tag key/value
func TestHcpbWorkers(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kmsCache, opts...)
	}
	connectionRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kmsCache)
	}
	var liveDur atomic.Int64
	liveDur.Store(int64(1 * time.Second))
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}

	// Stale/unalive kms worker aren't expected...
	server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: server.ManagedWorkerTag, Value: "true"}),
		server.WithAddress("old.kms.1"))
	// Sleep + 500ms longer than the liveness duration.
	time.Sleep(time.Duration(liveDur.Load()) + time.Second)

	server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: server.ManagedWorkerTag, Value: "true"}),
		server.WithAddress("kms.1"))
	server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: server.ManagedWorkerTag, Value: "true"}),
		server.WithAddress("kms.2"))
	server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: "unrelated_tag", Value: "true"}),
		server.WithAddress("unrelated_tag.kms.1"))

	// Shutdown workers will be removed from routes and sessions, but still returned
	// to downstream workers
	server.TestKmsWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: server.ManagedWorkerTag, Value: "true"}),
		server.WithAddress("shutdown.kms.3"), server.WithOperationalState(server.ShutdownOperationalState.String()))

	// PKI workers are also expected, if they have the managed worker tag
	serverRepo, err := serversRepoFn()
	require.NoError(err)
	var keyId string
	server.TestPkiWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: server.ManagedWorkerTag, Value: "true"}),
		server.WithTestPkiWorkerAuthorizedKeyId(&keyId))
	_, err = serverRepo.UpsertWorkerStatus(ctx, server.NewWorker(scope.Global.String(), server.WithAddress("pki.1")), server.WithKeyId(keyId))
	require.NoError(err)
	server.TestPkiWorker(t, conn, wrapper, server.WithWorkerTags(&server.Tag{Key: "unrelated_tag", Value: "true"}),
		server.WithTestPkiWorkerAuthorizedKeyId(&keyId))
	_, err = serverRepo.UpsertWorkerStatus(ctx, server.NewWorker(scope.Global.String(), server.WithAddress("unrelated_tag.pki.1")), server.WithKeyId(keyId))
	require.NoError(err)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kmsCache, &liveDur, fce)
	require.NotNil(t, s)

	res, err := s.ListHcpbWorkers(ctx, &pbs.ListHcpbWorkersRequest{})
	require.NoError(err)
	require.NotNil(res)
	expValues := []string{"kms.1", "kms.2", "shutdown.kms.3", "pki.1"}
	var gotValues []string
	for _, worker := range res.Workers {
		gotValues = append(gotValues, worker.Address)
	}
	assert.ElementsMatch(expValues, gotValues)
}

func TestStatistics(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kms)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kms, opts...)
	}
	connectionRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kms)
	}
	connectionRepoErrFn := func() (*session.ConnectionRepository, error) {
		return nil, fmt.Errorf("test error")
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}
	cases := []struct {
		name               string
		workerService      *workerServiceServer
		wantErrMsg         string
		expectedStatusCode codes.Code
		req                *pbs.StatisticsRequest
	}{
		{
			name:               "empty worker id",
			workerService:      NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce),
			req:                &pbs.StatisticsRequest{},
			wantErrMsg:         "rpc error: code = InvalidArgument desc = worker id is empty",
			expectedStatusCode: codes.InvalidArgument,
		},
		{
			name:          "missing session connection repo",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoErrFn, nil, new(sync.Map), kms, new(atomic.Int64), fce),
			req: &pbs.StatisticsRequest{
				WorkerId: "w_1234567890",
				Sessions: []*pbs.SessionStatistics{
					{},
				},
			},
			wantErrMsg:         "rpc error: code = Internal desc = Error acquiring connection repo: test error",
			expectedStatusCode: codes.Internal,
		},
		{
			name:          "nil sessions",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce),
			req: &pbs.StatisticsRequest{
				WorkerId: "w_1234567890",
			},
		},
		{
			name:          "empty sessions",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce),
			req: &pbs.StatisticsRequest{
				WorkerId: "w_1234567890",
				Sessions: []*pbs.SessionStatistics{},
			},
		},
		{
			name:          "empty session id",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce),
			req: &pbs.StatisticsRequest{
				WorkerId: "w_1234567890",
				Sessions: []*pbs.SessionStatistics{
					{},
				},
			},
			wantErrMsg:         "rpc error: code = InvalidArgument desc = session id is empty",
			expectedStatusCode: codes.InvalidArgument,
		},
		{
			name:          "empty connection id",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce),
			req: &pbs.StatisticsRequest{
				WorkerId: "w_1234567890",
				Sessions: []*pbs.SessionStatistics{
					{
						SessionId: "s_1234567890",
						Connections: []*pbs.Connection{
							{},
						},
					},
				},
			},
			wantErrMsg:         "rpc error: code = InvalidArgument desc = connection id is empty",
			expectedStatusCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.workerService.Statistics(context.Background(), tc.req)
			require.NotNil(got)
			if tc.wantErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tc.wantErrMsg)
				actualStatus, ok := status.FromError(err)
				require.True(ok)
				assert.Equal(tc.expectedStatusCode, actualStatus.Code())
				return
			}
			require.NoError(err)
		})
	}

	// update the bytes up and bytes down for an active session and close an orphaned session connection
	t.Run("happy path", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		connectionRepoFn := func() (*session.ConnectionRepository, error) {
			return session.NewConnectionRepository(ctx, rw, rw, kms, session.WithWorkerStateDelay(0))
		}
		sessRepo, err := sessionRepoFn()
		require.NoError(err)
		connRepo, err := connectionRepoFn()
		require.NoError(err)

		w := server.TestKmsWorker(t, conn, wrapper)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		authToken := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		userId := authToken.GetIamUserId()
		hostCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
		hostSet := static.TestSets(t, conn, hostCatalog.GetPublicId(), 1)[0]
		host := static.TestHosts(t, conn, hostCatalog.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hostSet.GetPublicId(), []*static.Host{host})
		tar := tcp.TestTarget(
			context.Background(),
			t, conn, prj.GetPublicId(), "test",
			target.WithHostSources([]string{hostSet.GetPublicId()}),
			target.WithSessionConnectionLimit(-1),
		)
		s1 := session.TestSession(t, conn, wrapper, session.ComposedOf{
			UserId:          userId,
			HostId:          host.GetPublicId(),
			TargetId:        tar.GetPublicId(),
			HostSetId:       hostSet.GetPublicId(),
			AuthTokenId:     authToken.GetPublicId(),
			ProjectId:       prj.GetPublicId(),
			Endpoint:        "tcp://127.0.0.1:22",
			ConnectionLimit: 10,
		})
		s1, _, err = sessRepo.ActivateSession(context.Background(), s1.PublicId, s1.Version, session.TestTofu(t))
		require.NoError(err)
		c1, err := connRepo.AuthorizeConnection(context.Background(), s1.PublicId, w.GetPublicId())
		require.NoError(err)

		s2 := session.TestSession(t, conn, wrapper, session.ComposedOf{
			UserId:          userId,
			HostId:          host.GetPublicId(),
			TargetId:        tar.GetPublicId(),
			HostSetId:       hostSet.GetPublicId(),
			AuthTokenId:     authToken.GetPublicId(),
			ProjectId:       prj.GetPublicId(),
			Endpoint:        "tcp://127.0.0.1:22",
			ConnectionLimit: 10,
		})
		s2, _, err = sessRepo.ActivateSession(context.Background(), s2.PublicId, s2.Version, session.TestTofu(t))
		require.NoError(err)
		c2, err := connRepo.AuthorizeConnection(context.Background(), s2.PublicId, w.PublicId)
		require.NoError(err)

		var expectedBytesUp int64 = 1024
		var expectedBytesDown int64 = 2048
		workerService := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kms, new(atomic.Int64), fce)
		got, err := workerService.Statistics(context.Background(), &pbs.StatisticsRequest{
			WorkerId: w.GetPublicId(),
			Sessions: []*pbs.SessionStatistics{
				{
					SessionId: s1.PublicId,
					Connections: []*pbs.Connection{
						{
							ConnectionId: c1.PublicId,
							BytesUp:      expectedBytesUp,
							BytesDown:    expectedBytesDown,
							Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
						},
					},
				},
			},
		})
		require.NoError(err)
		assert.NotNil(got)

		conn, err := connRepo.LookupConnection(context.Background(), c1.PublicId)
		require.NoError(err)
		assert.Equal(expectedBytesUp, conn.BytesUp)
		assert.Equal(expectedBytesDown, conn.BytesDown)
		assert.Equal(session.StatusAuthorized, session.ConnectionStatusFromString(conn.Status))

		conn, err = connRepo.LookupConnection(context.Background(), c2.PublicId)
		require.NoError(err)
		assert.Empty(conn.BytesUp)
		assert.Empty(conn.BytesDown)
		assert.Equal(session.StatusClosed, session.ConnectionStatusFromString(conn.Status))
	})
}

func TestSessionInfo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, testKms)
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, testKms)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, testKms, opts...)
	}
	connectionRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, testKms)
	}
	serversErrRepoFn := func() (*server.Repository, error) {
		return nil, errors.New("unknown error")
	}
	sessionErrRepoFn := func(opt ...session.Option) (*session.Repository, error) {
		return nil, errors.New("unknown error")
	}
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)
	iam.TestScopes(t, iamRepo)
	workerId := server.TestPkiWorker(t, conn, wrapper).PublicId
	cases := []struct {
		name               string
		workerService      *workerServiceServer
		wantErrMsg         string
		expectedStatusCode codes.Code
		req                *pbs.SessionInfoRequest
		expectedResponse   *pbs.SessionInfoResponse
	}{
		{
			name:               "empty worker id",
			workerService:      NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), testKms, new(atomic.Int64), fce),
			req:                &pbs.SessionInfoRequest{},
			wantErrMsg:         "rpc error: code = InvalidArgument desc = worker id is empty",
			expectedStatusCode: codes.InvalidArgument,
		},
		{
			name:          "invalid unspecified session type",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), testKms, new(atomic.Int64), fce),
			req: &pbs.SessionInfoRequest{
				WorkerId: "w_1234567890",
				Sessions: []*pbs.Session{
					{
						SessionId:     "s_A",
						SessionType:   pbs.SessionType_SESSION_TYPE_UNSPECIFIED,
						SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
					},
				},
			},
			wantErrMsg:         "rpc error: code = InvalidArgument desc = unspecified session type",
			expectedStatusCode: codes.InvalidArgument,
		},
		{
			name:          "invalid unknown session type",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), testKms, new(atomic.Int64), fce),
			req: &pbs.SessionInfoRequest{
				WorkerId: "w_1234567890",
				Sessions: []*pbs.Session{
					{
						SessionId:     "s_A",
						SessionType:   pbs.SessionType(-1),
						SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
					},
				},
			},
			wantErrMsg:         "rpc error: code = InvalidArgument desc = unknown session type",
			expectedStatusCode: codes.InvalidArgument,
		},
		{
			name:          "session repository error",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionErrRepoFn, connectionRepoFn, nil, new(sync.Map), testKms, new(atomic.Int64), fce),
			req: &pbs.SessionInfoRequest{
				WorkerId: "w_1234567890",
			},
			wantErrMsg:         "rpc error: code = Internal desc = Error acquiring repo to query session status: unknown error",
			expectedStatusCode: codes.Internal,
		},
		{
			name:          "server repository error",
			workerService: NewWorkerServiceServer(serversErrRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), testKms, new(atomic.Int64), fce),
			req: &pbs.SessionInfoRequest{
				WorkerId: "w_1234567890",
			},
			wantErrMsg:         "rpc error: code = Internal desc = Error acquiring repo to upsert session info status time: unknown error",
			expectedStatusCode: codes.Internal,
		},
		{
			name:          "ignore canceled and terminated sessions",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), testKms, new(atomic.Int64), fce),
			req: &pbs.SessionInfoRequest{
				WorkerId: workerId,
				Sessions: []*pbs.Session{
					{
						SessionId:     "s_A",
						SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
						SessionType:   pbs.SessionType_SESSION_TYPE_INGRESSED,
					},
					{
						SessionId:     "s_B",
						SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
						SessionType:   pbs.SessionType_SESSION_TYPE_INGRESSED,
					},
					{
						SessionId:     "s_C",
						SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
						SessionType:   pbs.SessionType_SESSION_TYPE_RECORDED,
					},
					{
						SessionId:     "s_D",
						SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
						SessionType:   pbs.SessionType_SESSION_TYPE_RECORDED,
					},
				},
			},
			expectedResponse: &pbs.SessionInfoResponse{},
		},
		{
			name:          "empty sessions",
			workerService: NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), testKms, new(atomic.Int64), fce),
			req: &pbs.SessionInfoRequest{
				WorkerId: workerId,
			},
			expectedResponse: &pbs.SessionInfoResponse{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.workerService.SessionInfo(context.Background(), tc.req)
			require.NotNil(got)
			if tc.wantErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tc.wantErrMsg)
				actualStatus, ok := status.FromError(err)
				require.True(ok)
				assert.Equal(tc.expectedStatusCode, actualStatus.Code())
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Len(got.NonActiveSessions, len(tc.expectedResponse.NonActiveSessions))
		})
	}

	t.Run("session canceled with active connections", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		sessionTypes := []pbs.SessionType{
			pbs.SessionType_SESSION_TYPE_INGRESSED,
			pbs.SessionType_SESSION_TYPE_RECORDED,
		}
		for _, sessionType := range sessionTypes {
			t.Run(sessionType.String(), func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				conn, _ := db.TestSetup(t, "postgres")
				rw := db.New(conn)
				wrapper := db.TestWrapper(t)
				testKms := kms.TestKms(t, conn, wrapper)
				org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

				serverRepo, err := server.NewRepository(ctx, rw, rw, testKms)
				require.NoError(err)
				c := server.NewController("test_controller1", server.WithAddress("127.0.0.1"))
				_, err = serverRepo.UpsertController(ctx, c)
				require.NoError(err)

				serversRepoFn := func() (*server.Repository, error) {
					return serverRepo, nil
				}
				workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
					return server.NewRepositoryStorage(ctx, rw, rw, testKms)
				}
				sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
					return session.NewRepository(ctx, rw, rw, testKms, opts...)
				}
				connRepoFn := func() (*session.ConnectionRepository, error) {
					return session.NewConnectionRepository(ctx, rw, rw, testKms)
				}
				fce := &fakeControllerExtension{
					reader: rw,
					writer: rw,
				}

				repo, err := sessionRepoFn()
				require.NoError(err)
				connRepo, err := connRepoFn()
				require.NoError(err)

				at := authtoken.TestAuthToken(t, conn, testKms, org.GetPublicId())
				uId := at.GetIamUserId()
				hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
				hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
				h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
				static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
				tar := tcp.TestTarget(
					ctx,
					t, conn, prj.GetPublicId(), "test",
					target.WithHostSources([]string{hs.GetPublicId()}),
					target.WithSessionConnectionLimit(-1),
				)

				worker1 := server.TestKmsWorker(t, conn, wrapper)
				sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
					UserId:          uId,
					HostId:          h.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hs.GetPublicId(),
					AuthTokenId:     at.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				tofu := session.TestTofu(t)
				sess, _, err = repo.ActivateSession(ctx, sess.PublicId, sess.Version, tofu)
				require.NoError(err)
				sess2 := session.TestSession(t, conn, wrapper, session.ComposedOf{
					UserId:          uId,
					HostId:          h.GetPublicId(),
					TargetId:        tar.GetPublicId(),
					HostSetId:       hs.GetPublicId(),
					AuthTokenId:     at.GetPublicId(),
					ProjectId:       prj.GetPublicId(),
					Endpoint:        "tcp://127.0.0.1:22",
					ConnectionLimit: 10,
				})
				tofu2 := session.TestTofu(t)
				sess2, _, err = repo.ActivateSession(ctx, sess2.PublicId, sess2.Version, tofu2)
				require.NoError(err)

				s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connRepoFn, nil, new(sync.Map), testKms, new(atomic.Int64), fce)
				require.NotNil(t, s)

				_, err = connRepo.AuthorizeConnection(ctx, sess.PublicId, worker1.PublicId)
				require.NoError(err)

				_, err = connRepo.AuthorizeConnection(ctx, sess2.PublicId, worker1.PublicId)
				require.NoError(err)

				_, err = repo.CancelSession(ctx, sess2.PublicId, sess.Version)
				require.NoError(err)

				got, err := s.SessionInfo(ctx, &pbs.SessionInfoRequest{
					WorkerId: worker1.GetPublicId(),
					Sessions: []*pbs.Session{
						{
							SessionId:     sess2.PublicId,
							SessionStatus: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
							SessionType:   sessionType,
						},
					},
				})
				require.NoError(err)
				require.NotNil(got)
				require.Len(got.NonActiveSessions, 1)
				actualNonActiveSession := got.NonActiveSessions[0]
				require.NotNil(actualNonActiveSession)
				assert.Equal(sess2.PublicId, actualNonActiveSession.SessionId)
				assert.Equal(pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING, actualNonActiveSession.SessionStatus)
				assert.Equal(sessionType, actualNonActiveSession.SessionType)
				assert.Empty(actualNonActiveSession.Connections)
			})
		}
	})
}

func TestRoutingInfo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	workerAuthRepoFn := func() (*server.WorkerAuthRepositoryStorage, error) {
		return server.NewRepositoryStorage(ctx, rw, rw, kmsCache)
	}
	sessionRepoFn := func(opts ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kmsCache, opts...)
	}
	connectionRepoFn := func() (*session.ConnectionRepository, error) {
		return session.NewConnectionRepository(ctx, rw, rw, kmsCache)
	}
	var liveDur atomic.Int64
	liveDur.Store(int64(1 * time.Second))
	fce := &fakeControllerExtension{
		reader: rw,
		writer: rw,
	}
	serverRepo, err := serversRepoFn()
	require.NoError(t, err)

	// Set up resources
	var w1KeyId, w2KeyId string
	w1 := server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&w1KeyId))
	_ = server.TestPkiWorker(t, conn, wrapper, server.WithTestPkiWorkerAuthorizedKeyId(&w2KeyId))
	w3 := server.TestKmsWorker(t, conn, wrapper, server.WithName("testworker3"))

	c := server.NewController("test_controller1", server.WithAddress("1.2.3.4"))
	_, err = serverRepo.UpsertController(ctx, c)
	require.NoError(t, err)

	s := NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, nil, new(sync.Map), kmsCache, &liveDur, fce)
	require.NotNil(t, s)
	require.NoError(t, err)

	t.Run("Missing worker status", func(t *testing.T) {
		req := &pbs.RoutingInfoRequest{}
		_, err := s.RoutingInfo(ctx, req)
		require.ErrorContains(t, err, "worker status is required")
	})

	t.Run("Missing key ID and public Id", func(t *testing.T) {
		req := &pbs.RoutingInfoRequest{
			WorkerStatus: &pb.ServerWorkerStatus{
				PublicId: "",
				KeyId:    "",
				Address:  "2.3.4.5:8080",
				Tags: []*pb.TagPair{
					{Key: "tag1", Value: "value1"},
					{Key: "tag2", Value: "value2"},
				},
				ReleaseVersion:    "Boundary v0.18.0",
				OperationalState:  server.ActiveOperationalState.String(),
				LocalStorageState: server.AvailableLocalStorageState.String(),
			},
			UpdateTags:                            true,
			ConnectedUnmappedWorkerKeyIdentifiers: []string{w2KeyId, "worker-key-2"},
			ConnectedWorkerPublicIds:              []string{w3.PublicId, "worker-3"},
		}
		_, err := s.RoutingInfo(ctx, req)
		require.ErrorContains(t, err, "public id, key id and name are not set in the request; one is required")
	})

	t.Run("Missing address", func(t *testing.T) {
		req := &pbs.RoutingInfoRequest{
			WorkerStatus: &pb.ServerWorkerStatus{
				PublicId: "",
				KeyId:    w1KeyId,
				Address:  "",
				Tags: []*pb.TagPair{
					{Key: "tag1", Value: "value1"},
					{Key: "tag2", Value: "value2"},
				},
				ReleaseVersion:    "Boundary v0.18.0",
				OperationalState:  server.ActiveOperationalState.String(),
				LocalStorageState: server.AvailableLocalStorageState.String(),
			},
			UpdateTags:                            true,
			ConnectedUnmappedWorkerKeyIdentifiers: []string{w2KeyId, "worker-key-2"},
			ConnectedWorkerPublicIds:              []string{w3.PublicId, "worker-3"},
		}
		_, err := s.RoutingInfo(ctx, req)
		require.ErrorContains(t, err, "address is not set but is required")
	})

	t.Run("Missing release version", func(t *testing.T) {
		req := &pbs.RoutingInfoRequest{
			WorkerStatus: &pb.ServerWorkerStatus{
				PublicId: "",
				KeyId:    w1KeyId,
				Address:  "2.3.4.5:8080",
				Tags: []*pb.TagPair{
					{Key: "tag1", Value: "value1"},
					{Key: "tag2", Value: "value2"},
				},
				ReleaseVersion:    "",
				OperationalState:  server.ActiveOperationalState.String(),
				LocalStorageState: server.AvailableLocalStorageState.String(),
			},
			UpdateTags:                            true,
			ConnectedUnmappedWorkerKeyIdentifiers: []string{w2KeyId, "worker-key-2"},
			ConnectedWorkerPublicIds:              []string{w3.PublicId, "worker-3"},
		}
		_, err := s.RoutingInfo(ctx, req)
		require.ErrorContains(t, err, "release version is not set but is required")
	})

	t.Run("Missing operational state", func(t *testing.T) {
		req := &pbs.RoutingInfoRequest{
			WorkerStatus: &pb.ServerWorkerStatus{
				PublicId: "",
				KeyId:    w1KeyId,
				Address:  "2.3.4.5:8080",
				Tags: []*pb.TagPair{
					{Key: "tag1", Value: "value1"},
					{Key: "tag2", Value: "value2"},
				},
				ReleaseVersion:    "Boundary v0.18.0",
				OperationalState:  "",
				LocalStorageState: server.AvailableLocalStorageState.String(),
			},
			UpdateTags:                            true,
			ConnectedUnmappedWorkerKeyIdentifiers: []string{w2KeyId, "worker-key-2"},
			ConnectedWorkerPublicIds:              []string{w3.PublicId, "worker-3"},
		}
		_, err := s.RoutingInfo(ctx, req)
		require.ErrorContains(t, err, "operational state is not set but is required")
	})

	t.Run("Missing local storage state", func(t *testing.T) {
		req := &pbs.RoutingInfoRequest{
			WorkerStatus: &pb.ServerWorkerStatus{
				PublicId: "",
				KeyId:    w1KeyId,
				Address:  "2.3.4.5:8080",
				Tags: []*pb.TagPair{
					{Key: "tag1", Value: "value1"},
					{Key: "tag2", Value: "value2"},
				},
				ReleaseVersion:    "Boundary v0.18.0",
				OperationalState:  server.ActiveOperationalState.String(),
				LocalStorageState: "",
			},
			UpdateTags:                            true,
			ConnectedUnmappedWorkerKeyIdentifiers: []string{w2KeyId, "worker-key-2"},
			ConnectedWorkerPublicIds:              []string{w3.PublicId, "worker-3"},
		}
		_, err := s.RoutingInfo(ctx, req)
		require.ErrorContains(t, err, "local storage state is not set but is required")
	})

	t.Run("Successful first and second request (PKI worker)", func(t *testing.T) {
		req := &pbs.RoutingInfoRequest{
			WorkerStatus: &pb.ServerWorkerStatus{
				PublicId: "", // Not set on the first request
				KeyId:    w1KeyId,
				Address:  "2.3.4.5:8080",
				Tags: []*pb.TagPair{
					{Key: "tag1", Value: "value1"},
					{Key: "tag2", Value: "value2"},
				},
				ReleaseVersion:    "Boundary v0.18.0",
				OperationalState:  server.ActiveOperationalState.String(),
				LocalStorageState: server.AvailableLocalStorageState.String(),
			},
			UpdateTags:                            true,
			ConnectedUnmappedWorkerKeyIdentifiers: []string{w2KeyId, "worker-key-2"},
			ConnectedWorkerPublicIds:              []string{w3.PublicId, "worker-3"},
		}
		resp, err := s.RoutingInfo(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)

		assert.Equal(t, resp.WorkerId, w1.PublicId)
		assert.Equal(t, resp.CalculatedUpstreamAddresses, []string{c.Address})
		assert.Equal(t, resp.AuthorizedDownstreamWorkers.UnmappedWorkerKeyIdentifiers, []string{w2KeyId})
		assert.Equal(t, resp.AuthorizedDownstreamWorkers.WorkerPublicIds, []string{w3.PublicId})

		w1, err := serverRepo.LookupWorker(ctx, resp.WorkerId)
		require.NoError(t, err)

		assert.Equal(t, w1.Address, "2.3.4.5:8080")
		expTags := server.Tags{
			"tag1": []string{"value1"},
			"tag2": []string{"value2"},
		}
		assert.Equal(t, len(expTags), len(w1.ConfigTags))
		for k, v := range expTags {
			assert.ElementsMatch(t, v, w1.ConfigTags[k])
		}
		assert.Equal(t, w1.ReleaseVersion, "Boundary v0.18.0")
		assert.EqualValues(t, w1.OperationalState, server.ActiveOperationalState)
		assert.EqualValues(t, w1.LocalStorageState, server.AvailableLocalStorageState)

		// Now send the subsequent routing info request
		req.WorkerStatus.PublicId = w1.PublicId // Only set on subsequent requests
		resp, err = s.RoutingInfo(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)

		assert.Equal(t, resp.WorkerId, w1.PublicId)
		assert.Equal(t, resp.CalculatedUpstreamAddresses, []string{c.Address})
		assert.Equal(t, resp.AuthorizedDownstreamWorkers.UnmappedWorkerKeyIdentifiers, []string{w2KeyId})
		assert.Equal(t, resp.AuthorizedDownstreamWorkers.WorkerPublicIds, []string{w3.PublicId})

		w1, err = serverRepo.LookupWorker(ctx, resp.WorkerId)
		require.NoError(t, err)

		assert.Equal(t, w1.Address, "2.3.4.5:8080")
		assert.Equal(t, len(expTags), len(w1.ConfigTags))
		for k, v := range expTags {
			assert.ElementsMatch(t, v, w1.ConfigTags[k])
		}
		assert.Equal(t, w1.ReleaseVersion, "Boundary v0.18.0")
		assert.EqualValues(t, w1.OperationalState, server.ActiveOperationalState)
		assert.EqualValues(t, w1.LocalStorageState, server.AvailableLocalStorageState)
	})

	t.Run("Successful first and second request (KMS worker)", func(t *testing.T) {
		req := &pbs.RoutingInfoRequest{
			WorkerStatus: &pb.ServerWorkerStatus{
				PublicId: "", // Not set on the first request
				Name:     "testworker3",
				Address:  "2.3.4.5:8080",
				Tags: []*pb.TagPair{
					{Key: "tag1", Value: "value1"},
					{Key: "tag2", Value: "value2"},
				},
				ReleaseVersion:    "Boundary v0.18.0",
				OperationalState:  server.ActiveOperationalState.String(),
				LocalStorageState: server.AvailableLocalStorageState.String(),
			},
			UpdateTags:                            true,
			ConnectedUnmappedWorkerKeyIdentifiers: []string{w2KeyId, "worker-key-2"},
			ConnectedWorkerPublicIds:              []string{w1.PublicId, "worker-4"},
		}
		resp, err := s.RoutingInfo(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)

		assert.Equal(t, resp.WorkerId, w3.PublicId)
		assert.Equal(t, resp.CalculatedUpstreamAddresses, []string{c.Address})
		assert.Equal(t, resp.AuthorizedDownstreamWorkers.UnmappedWorkerKeyIdentifiers, []string{w2KeyId})
		assert.Equal(t, resp.AuthorizedDownstreamWorkers.WorkerPublicIds, []string{w1.PublicId})

		w3, err := serverRepo.LookupWorker(ctx, resp.WorkerId)
		require.NoError(t, err)

		assert.Equal(t, w3.Address, "2.3.4.5:8080")
		expTags := server.Tags{
			"tag1": []string{"value1"},
			"tag2": []string{"value2"},
		}
		assert.Equal(t, len(expTags), len(w3.ConfigTags))
		for k, v := range expTags {
			assert.ElementsMatch(t, v, w3.ConfigTags[k])
		}
		assert.Equal(t, w3.ReleaseVersion, "Boundary v0.18.0")
		assert.EqualValues(t, w3.OperationalState, server.ActiveOperationalState)
		assert.EqualValues(t, w3.LocalStorageState, server.AvailableLocalStorageState)

		// Now send the subsequent routing info request
		req.WorkerStatus.PublicId = w3.PublicId // Only set on subsequent requests
		resp, err = s.RoutingInfo(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)

		assert.Equal(t, resp.WorkerId, w3.PublicId)
		assert.Equal(t, resp.CalculatedUpstreamAddresses, []string{c.Address})
		assert.Equal(t, resp.AuthorizedDownstreamWorkers.UnmappedWorkerKeyIdentifiers, []string{w2KeyId})
		assert.Equal(t, resp.AuthorizedDownstreamWorkers.WorkerPublicIds, []string{w1.PublicId})

		w1, err = serverRepo.LookupWorker(ctx, resp.WorkerId)
		require.NoError(t, err)

		assert.Equal(t, w3.Address, "2.3.4.5:8080")
		assert.Equal(t, len(expTags), len(w3.ConfigTags))
		for k, v := range expTags {
			assert.ElementsMatch(t, v, w3.ConfigTags[k])
		}
		assert.Equal(t, w3.ReleaseVersion, "Boundary v0.18.0")
		assert.EqualValues(t, w3.OperationalState, server.ActiveOperationalState)
		assert.EqualValues(t, w3.LocalStorageState, server.AvailableLocalStorageState)
	})
}
