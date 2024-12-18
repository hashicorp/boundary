package groups_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/boundary/globals"
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

// Test Dimension
//  Role - which scope the role is created in
// 		- global level
// 		- org level
// 		- project level
//	Grant - what IAM grant scope is set for the permission
// 		- global: descendant
//		- org: children
// 		- project
//	Resource - where resources are created (group)
// 		- global
//			- org1
// 				- project1
//			- org2
// 				- project2

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
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	atRepoFn := func() (*authtoken.Repository, error) {
		return atRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}

	org, proj := iam.TestScopes(t, iamRepo)
	globalGroup := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))
	orgGroup := iam.TestGroup(t, conn, org.GetPublicId(), iam.WithDescription("org"), iam.WithName("org"))
	projGroup := iam.TestGroup(t, conn, proj.GetPublicId(), iam.WithDescription("project"), iam.WithName("project"))

	authMethod := password.TestAuthMethods(t, conn, globals.GlobalPrefix, 1)[0]
	testcases := []struct {
		name            string
		grantString     string
		roleScope       string
		roleGrantScopes []string
		getIdFound      map[string]bool
	}{
		{
			name:            "global_role_grant_this",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       globals.GlobalPrefix,
			roleGrantScopes: []string{globals.GrantScopeThis},
			getIdFound: map[string]bool{
				globalGroup.PublicId: true,
				orgGroup.PublicId:    false,
				projGroup.PublicId:   false,
			},
		},
		{
			name:            "global_role_grant_children",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       globals.GlobalPrefix,
			roleGrantScopes: []string{globals.GrantScopeChildren},
			getIdFound: map[string]bool{
				globalGroup.PublicId: false,
				orgGroup.PublicId:    true,
				projGroup.PublicId:   false,
			},
		},
		{
			name:            "global_role_grant_descendant",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       globals.GlobalPrefix,
			roleGrantScopes: []string{globals.GrantScopeDescendants},
			getIdFound: map[string]bool{
				globalGroup.PublicId: false,
				orgGroup.PublicId:    true,
				projGroup.PublicId:   true,
			},
		},
		{
			name:            "global_role_grant_this_children",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       globals.GlobalPrefix,
			roleGrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			getIdFound: map[string]bool{
				globalGroup.PublicId: true,
				orgGroup.PublicId:    true,
				projGroup.PublicId:   false,
			},
		},
		{
			name:            "global_role_grant_this_descendant",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       globals.GlobalPrefix,
			roleGrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
			getIdFound: map[string]bool{
				globalGroup.PublicId: true,
				orgGroup.PublicId:    true,
				projGroup.PublicId:   true,
			},
		},
		{
			name:            "org_role_grant_this",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       org.GetPublicId(),
			roleGrantScopes: []string{globals.GrantScopeThis},
			getIdFound: map[string]bool{
				globalGroup.PublicId: false,
				orgGroup.PublicId:    true,
				projGroup.PublicId:   false,
			},
		},
		{
			name:            "org_role_grant_children",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       org.GetPublicId(),
			roleGrantScopes: []string{globals.GrantScopeChildren},
			getIdFound: map[string]bool{
				globalGroup.PublicId: false,
				orgGroup.PublicId:    false,
				projGroup.PublicId:   true,
			},
		},
		{
			name:            "org_role_grant_this_and_children",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       org.GetPublicId(),
			roleGrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			getIdFound: map[string]bool{
				globalGroup.PublicId: false,
				orgGroup.PublicId:    true,
				projGroup.PublicId:   true,
			},
		},
		{
			name:            "project_role_grant_this",
			grantString:     "id=*;type=*;actions=*",
			roleScope:       proj.GetPublicId(),
			roleGrantScopes: []string{globals.GrantScopeThis},
			getIdFound: map[string]bool{
				globalGroup.PublicId: false,
				orgGroup.PublicId:    false,
				projGroup.PublicId:   true,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// this creates everything required to get a token and creates context with auth token
			acct := password.TestAccount(t, conn, authMethod.GetPublicId(), uuid.NewString())
			user := iam.TestUser(t, iamRepo, globals.GlobalPrefix, iam.WithAccountIds(acct.GetPublicId()))
			role := iam.TestRole(t, conn, tc.roleScope, iam.WithGrantScopeIds(tc.roleGrantScopes))
			_ = iam.TestRoleGrant(t, conn, role.PublicId, tc.grantString)
			_ = iam.TestUserRole(t, conn, role.PublicId, user.PublicId)
			fullGrantToken, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := auth.NewVerifierContext(requests.NewRequestContext(ctx, requests.WithUserId(user.GetPublicId())),
				repoFn, atRepoFn, serversRepoFn, kmsCache, &authpb.RequestInfo{
					PublicId:    fullGrantToken.PublicId,
					Token:       fullGrantToken.GetToken(),
					TokenFormat: uint32(auth.AuthTokenTypeBearer),
				})
			for id, found := range tc.getIdFound {
				_, err := s.GetGroup(fullGrantAuthCtx, &pbs.GetGroupRequest{
					Id: id,
				})
				// not found means expect error
				if !found {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

			}
		})
	}

}
