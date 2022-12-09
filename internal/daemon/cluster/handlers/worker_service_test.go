package handlers_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/authtoken"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
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

func TestLookupSession(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
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

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, new(sync.Map), kms, new(atomic.Int64))
	require.NotNil(t, s)

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
			wantErrMsg: "rpc error: code = Internal desc = Did not receive worker id when looking up session but filtering is enabled",
		},
		{
			name: "nonexistant worker id",
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

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kmsCache)
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

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, new(sync.Map), kmsCache, new(atomic.Int64))
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
		return server.NewRepository(rw, rw, kms)
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
	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, new(sync.Map), kms, new(atomic.Int64))
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
// returned workers are those of kms type with the expected tag key/value
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
		return server.NewRepository(rw, rw, kmsCache)
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

	for i := 0; i < 3; i++ {
		var opt []server.Option
		if i > 0 {
			// Out of three KMS workers we expect to see two
			opt = append(opt, server.WithWorkerTags(&server.Tag{Key: handlers.ManagedWorkerTagKey, Value: "true"}))
		}
		server.TestKmsWorker(t, conn, wrapper, append(opt, server.WithAddress(fmt.Sprintf("kms.%d", i)))...)
		server.TestPkiWorker(t, conn, wrapper, opt...)
	}

	s := handlers.NewWorkerServiceServer(serversRepoFn, workerAuthRepoFn, sessionRepoFn, connectionRepoFn, new(sync.Map), kmsCache, new(atomic.Int64))
	require.NotNil(t, s)

	res, err := s.ListHcpbWorkers(ctx, &pbs.ListHcpbWorkersRequest{})
	require.NoError(err)
	require.NotNil(res)
	expValues := []string{"kms.1", "kms.2"}
	var gotValues []string
	for _, worker := range res.Workers {
		gotValues = append(gotValues, worker.Address)
	}
	assert.ElementsMatch(expValues, gotValues)
}
