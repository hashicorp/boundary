package groups_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/stretchr/testify/require"
)

func TestGrants_Get(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	atRepoFn := func() (*authtoken.Repository, error) {
		return atRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}

	org, proj := iam.TestScopes(t, iamRepo)
	authMethod := password.TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	// auth account is only used to join auth method to user.
	// We don't do anything else with the auth account in the test setup.
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "myname")

	usr := iam.TestUser(t, iamRepo, org.GetPublicId(), iam.WithAccountIds(acct.GetPublicId()))
	role := iam.TestRole(t, conn, org.GetPublicId())
	_ = iam.TestRoleGrant(t, conn, role.PublicId, "id=*;type=*;actions=*;output_fields=*")
	_ = iam.TestUserRole(t, conn, role.PublicId, usr.PublicId)
	_ = iam.TestRoleGrantScope(t, conn, role.PublicId, proj.PublicId)

	orgGroup := iam.TestGroup(t, conn, org.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, orgGroup.GetPublicId(), usr.GetPublicId())

	projGroup := iam.TestGroup(t, conn, proj.GetPublicId(), iam.WithDescription("default"), iam.WithName("default"))
	_ = iam.TestGroupMember(t, conn, projGroup.GetPublicId(), usr.GetPublicId())

	token, err := atRepo.CreateAuthToken(ctx, usr, acct.GetPublicId())
	require.NoError(t, err)

	reqCtx := requests.NewRequestContext(ctx, requests.WithUserId(usr.GetPublicId()))
	authCtx := auth.NewVerifierContext(reqCtx, repoFn, atRepoFn, serversRepoFn, kmsCache, &authpb.RequestInfo{
		Path:        fmt.Sprintf("/v1/groups/%s", orgGroup.PublicId),
		Method:      "GET",
		PublicId:    token.PublicId,
		Token:       token.GetToken(),
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
	})
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)

	got, gErr := s.GetGroup(authCtx, &pbs.GetGroupRequest{
		Id: projGroup.PublicId,
	})
	require.NoError(t, gErr)
	fmt.Println(got)

	//if tc.err != nil {
	//	require.Error(gErr)
	//	assert.True(errors.Is(gErr, tc.err), "GetGroup(%+v) got error %v, wanted %v", req, gErr, tc.err)
	//}
	//
	//for _, tc := range cases {
	//	t.Run(tc.name, func(t *testing.T) {
	//		assert, require := assert.New(t), require.New(t)
	//		req := proto.Clone(toMerge).(*pbs.GetGroupRequest)
	//		proto.Merge(req, tc.req)
	//
	//		s, err := groups.NewService(ctx, repoFn, 1000)
	//		require.NoError(err, "Couldn't create new group service.")
	//
	//		got, gErr := s.GetGroup(auth.DisabledAuthTestContext(repoFn, tc.scopeId), req)
	//		if tc.err != nil {
	//			require.Error(gErr)
	//			assert.True(errors.Is(gErr, tc.err), "GetGroup(%+v) got error %v, wanted %v", req, gErr, tc.err)
	//		}
	//		assert.Empty(cmp.Diff(
	//			got,
	//			tc.res,
	//			protocmp.Transform(),
	//			cmpopts.SortSlices(func(a, b string) bool {
	//				return a < b
	//			}),
	//		), "GetGroup(%q) got response\n%q, wanted\n%q", req, got, tc.res)
	//	})
	//}
}
