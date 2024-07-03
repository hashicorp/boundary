// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/authtoken"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/db"
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
