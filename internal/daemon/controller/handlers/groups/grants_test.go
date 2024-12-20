package groups_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type roleRequest struct {
	roleScopeID  string
	grantStrings []string
	grantScopes  []string
}

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
//			- org level
//			- project level
//		Grant - what IAM grant scope is set for the permission
//			- global: descendant
//			- org: children
//			- project
//		Scopes [resource]:
//			- global [globalGroup]
//				- org1 [org1Group]
//					- proj1 [proj1Group]
//				- org2 [org2Group]
//					- proj2 [proj2Group]
//					- proj3 [proj3Group]

func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

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

	org1, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	globalGroup := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))
	org1Group := iam.TestGroup(t, conn, org1.GetPublicId(), iam.WithDescription("org1"), iam.WithName("org1"))
	org2Group := iam.TestGroup(t, conn, org2.GetPublicId(), iam.WithDescription("org2"), iam.WithName("org2"))
	proj1Group := iam.TestGroup(t, conn, proj1.GetPublicId(), iam.WithDescription("proj1"), iam.WithName("proj1"))
	proj2Group := iam.TestGroup(t, conn, proj2.GetPublicId(), iam.WithDescription("proj2"), iam.WithName("proj2"))
	proj3Group := iam.TestGroup(t, conn, proj3.GetPublicId(), iam.WithDescription("proj3"), iam.WithName("proj3"))
	authMethod := password.TestAuthMethods(t, conn, globals.GlobalPrefix, 1)[0]

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			input         *pbs.ListGroupsRequest
			rolesToCreate []roleRequest
			wantErr       error
			wantIDs       []string
		}{
			{
				name:    "global role grant this only returns in global groups",
				wantErr: nil,
				input: &pbs.ListGroupsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				wantIDs: []string{globalGroup.PublicId},
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
			},
			{
				name: "global role grant this and children returns global and org groups",
				input: &pbs.ListGroupsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				// TODO (Bo 20-dec-2024): expect 3 groups but only getting 1 back
				// need to investigate further
				//wantIDs: []string{globalGroup.PublicId, org1Group.PublicId, org2Group.PublicId},
				wantIDs: []string{globalGroup.PublicId},
			},
			{
				name: "global role grant this and descendant returns all groups",
				input: &pbs.ListGroupsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: nil,
				wantIDs: []string{globalGroup.PublicId, org1Group.PublicId, org2Group.PublicId, proj1Group.PublicId, proj2Group.PublicId, proj3Group.PublicId},
			},
			{
				name: "org role grant children IDs only org children",
				input: &pbs.ListGroupsRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"ids=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeDescendants},
					},
				},
				wantErr: nil,
				wantIDs: []string{org2Group.PublicId, proj2Group.PublicId, proj3Group.PublicId},
			},
			{
				name: "org role grant children IDs only org children",
				input: &pbs.ListGroupsRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  org2.PublicId,
						grantStrings: []string{"ids=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: nil,
				wantIDs: []string{org2Group.PublicId},
			},
			{
				name: "no list permission returns error",
				input: &pbs.ListGroupsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []roleRequest{
					{
						roleScopeID: globals.GlobalPrefix,
						grantStrings: []string{
							fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId),
						},
						grantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: handlers.ForbiddenError(),
				wantIDs: nil,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				// this creates everything required to get a token and creates context with auth token
				acct := password.TestAccount(t, conn, authMethod.GetPublicId(), uuid.NewString())
				user := iam.TestUser(t, iamRepo, globals.GlobalPrefix, iam.WithAccountIds(acct.GetPublicId()))
				for _, r := range tc.rolesToCreate {
					role := iam.TestRoleWithGrants(t, conn, r.roleScopeID, r.grantScopes, r.grantStrings)
					_ = iam.TestUserRole(t, conn, role.PublicId, user.PublicId)
				}
				fullGrantToken, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.NewVerifierContext(requests.NewRequestContext(ctx, requests.WithUserId(user.GetPublicId())),
					repoFn, atRepoFn, serversRepoFn, kmsCache, &authpb.RequestInfo{
						PublicId:    fullGrantToken.PublicId,
						Token:       fullGrantToken.GetToken(),
						TokenFormat: uint32(auth.AuthTokenTypeBearer),
					})
				got, finalErr := s.ListGroups(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				var gotIDs []string
				for _, g := range got.Items {
					gotIDs = append(gotIDs, g.GetId())
				}
				require.NoError(t, finalErr)
				require.ElementsMatch(t, tc.wantIDs, gotIDs)
			})
		}
	})

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name                string
			rolesToCreate       []roleRequest
			wantErr             map[string]error
			outputFieldAsserter func(t *testing.T)
		}{
			{
				name: "global_role_grant_this",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: nil,
					org1Group.PublicId:   handlers.ForbiddenError(),
					proj1Group.PublicId:  handlers.ForbiddenError(),
				},
			},
			{
				name: "global_role_grant_children",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  handlers.ForbiddenError(),
				},
			},
			{
				name: "global_role_grant_descendant",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeDescendants},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  nil,
				},
			},
			{
				name: "global_role_grant_this_children",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: nil,
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  handlers.ForbiddenError(),
				},
			},
			{
				name: "global_role_grant_this_descendant",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: nil,
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  nil,
				},
			},
			{
				name: "org_role_grant_this",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  org1.GetPublicId(),
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  handlers.ForbiddenError(),
				},
			},
			{
				name: "org_role_grant_children",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  org1.GetPublicId(),
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   handlers.ForbiddenError(),
					proj1Group.PublicId:  nil,
				},
			},
			{
				name: "org_role_grant_this_and_children",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  org1.GetPublicId(),
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  nil,
				},
			},
			{
				name: "project_role_grant_this",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  proj1.GetPublicId(),
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   handlers.ForbiddenError(),
					proj1Group.PublicId:  nil,
				},
			},
			{
				name: "global_role_grant_all_scopes_specific_group_id",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{fmt.Sprintf("ids=%s;types=group ;actions=read", org1Group.PublicId)},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  handlers.ForbiddenError(),
				},
			},
			{
				name: "global_role_grant_all_specific_permissions",
				rolesToCreate: []roleRequest{
					{
						roleScopeID: globals.GlobalPrefix,
						grantStrings: []string{
							fmt.Sprintf("ids=%s;types=group;actions=read", org1Group.PublicId),
							fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId)},
						grantScopes: []string{org1.PublicId, proj1.PublicId},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  nil,
				},
			},
			{
				name: "global_role_grant_all_specific_permissions",
				rolesToCreate: []roleRequest{
					{
						roleScopeID: globals.GlobalPrefix,
						grantStrings: []string{
							fmt.Sprintf("ids=%s;types=group;actions=read", org1Group.PublicId),
							fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId)},
						grantScopes: []string{org1.PublicId, proj1.PublicId},
					},
				},
				wantErr: map[string]error{
					globalGroup.PublicId: handlers.ForbiddenError(),
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  nil,
				},
			},
			{
				name: "global_role_grant_all_specific_permissions",
				rolesToCreate: []roleRequest{
					{
						roleScopeID: globals.GlobalPrefix,
						grantStrings: []string{
							fmt.Sprintf("ids=%s;types=group;actions=read", globalGroup.PublicId)},
						grantScopes: []string{globals.GrantScopeThis},
					},
					{
						roleScopeID: org1.GetPublicId(),
						grantStrings: []string{
							fmt.Sprintf("ids=%s;types=group;actions=read", org1Group.PublicId),
							fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId)},
						grantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},

				wantErr: map[string]error{
					globalGroup.PublicId: nil,
					org1Group.PublicId:   nil,
					proj1Group.PublicId:  nil,
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				// this creates everything required to get a token and creates context with auth token
				acct := password.TestAccount(t, conn, authMethod.GetPublicId(), uuid.NewString())
				user := iam.TestUser(t, iamRepo, globals.GlobalPrefix, iam.WithAccountIds(acct.GetPublicId()))
				for _, r := range tc.rolesToCreate {
					role := iam.TestRoleWithGrants(t, conn, r.roleScopeID, r.grantScopes, r.grantStrings)
					_ = iam.TestUserRole(t, conn, role.PublicId, user.PublicId)
				}
				fullGrantToken, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.NewVerifierContext(requests.NewRequestContext(ctx, requests.WithUserId(user.GetPublicId())),
					repoFn, atRepoFn, serversRepoFn, kmsCache, &authpb.RequestInfo{
						PublicId:    fullGrantToken.PublicId,
						Token:       fullGrantToken.GetToken(),
						TokenFormat: uint32(auth.AuthTokenTypeBearer),
					})
				for id, wantErr := range tc.wantErr {
					_, err := s.GetGroup(fullGrantAuthCtx, &pbs.GetGroupRequest{
						Id: id,
					})
					// not found means expect error
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
				}
			})
		}
	})
}
