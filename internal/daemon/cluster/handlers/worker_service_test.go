package handlers_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/authtoken"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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
	sessionRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
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
		ScopeId:     prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	egressSess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     prj.GetPublicId(),
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
			Credential: &pbs.Credential_UsernamePassword{
				UsernamePassword: &pbs.UsernamePassword{
					Username: "another-username",
					Password: "a different password",
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
	err = repo.AddSessionCredentials(ctx, egressSess.ScopeId, egressSess.GetPublicId(), workerCreds)
	require.NoError(t, err)

	s := handlers.NewWorkerServiceServer(serversRepoFn, sessionRepoFn, connectionRepoFn, new(sync.Map), kms)
	require.NotNil(t, s)

	cases := []struct {
		name       string
		wantErr    bool
		wantErrMsg string
		want       *pbs.LookupSessionResponse
		sessionId  string
	}{
		{
			name:       "Invalid session id",
			sessionId:  "s_fakesession",
			wantErr:    true,
			wantErrMsg: "rpc error: code = PermissionDenied desc = Unknown session ID.",
		},
		{
			name:      "Valid",
			sessionId: sess.PublicId,
			want: &pbs.LookupSessionResponse{
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
			name:      "Valid-with-egress-creds",
			sessionId: egressSess.PublicId,
			want: &pbs.LookupSessionResponse{
				ConnectionLimit: 1,
				ConnectionsLeft: 1,
				Version:         1,
				Endpoint:        egressSess.Endpoint,
				HostId:          egressSess.HostId,
				HostSetId:       egressSess.HostSetId,
				TargetId:        egressSess.TargetId,
				UserId:          egressSess.UserId,
				Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
				Credentials:     creds,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := &pbs.LookupSessionRequest{
				SessionId: tc.sessionId,
			}

			got, err := s.LookupSession(ctx, req)
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
					cmpopts.IgnoreUnexported(pbs.LookupSessionResponse{}, pbs.Credential{}, pbs.UsernamePassword{}),
					cmpopts.IgnoreFields(pbs.LookupSessionResponse{}, "Expiration", "Authorization"),
				),
			)
		})
	}
}
