package sessions_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestGetSession(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)

	iamRepo := iam.TestRepo(t, conn, wrap)

	rw := db.New(conn)
	sessRepo, err := session.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	sessRepoFn := func() (*session.Repository, error) {
		return sessRepo, nil
	}

	o, p := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, p.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := target.TestTcpTarget(t, conn, p.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))

	sess := session.TestSession(t, conn, wrap, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     p.GetPublicId(),
	})

	wireSess := &pb.Session{
		Id:             sess.GetPublicId(),
		ScopeId:        p.GetPublicId(),
		AuthTokenId:    at.GetPublicId(),
		UserId:         at.GetIamUserId(),
		TargetId:       sess.TargetId,
		HostSetId:      sess.HostSetId,
		HostId:         sess.HostId,
		Version:        sess.Version,
		Status:         session.StatusPending.String(),
		UpdatedTime:    sess.UpdateTime.GetTimestamp(),
		CreatedTime:    sess.CreateTime.GetTimestamp(),
		ExpirationTime: sess.ExpirationTime.GetTimestamp(),
		Scope:          &scopes.ScopeInfo{Id: p.GetPublicId(), Type: scope.Project.String()},
		States:         []*pb.SessionState{{Status: session.StatusPending.String(), StartTime: sess.CreateTime.GetTimestamp()}},
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetSessionRequest
		res     *pbs.GetSessionResponse
		errCode codes.Code
	}{
		{
			name:    "Get a session",
			scopeId: sess.ScopeId,
			req:     &pbs.GetSessionRequest{Id: sess.GetPublicId()},
			res:     &pbs.GetSessionResponse{Item: wireSess},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existant Session",
			req:     &pbs.GetSessionRequest{Id: session.SessionPrefix + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetSessionRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetSessionRequest{Id: session.SessionPrefix + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := sessions.NewService(sessRepoFn, iamRepoFn)
			require.NoError(err, "Couldn't create new session service.")

			got, gErr := s.GetSession(auth.DisabledAuthTestContext(auth.WithScopeId(tc.scopeId)), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetSession(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform()), "GetSession(%q) got response\n%q, wanted\n%q", tc.req, got, tc.res)
		})
	}
}
