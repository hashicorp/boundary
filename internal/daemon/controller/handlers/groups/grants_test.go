// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package groups_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	cauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGrants_ListGroups(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	org1, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	globalGroup := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))
	org1Group := iam.TestGroup(t, conn, org1.GetPublicId(), iam.WithDescription("org1"), iam.WithName("org1"))
	org2Group := iam.TestGroup(t, conn, org2.GetPublicId(), iam.WithDescription("org2"), iam.WithName("org2"))
	proj1Group := iam.TestGroup(t, conn, proj1.GetPublicId(), iam.WithDescription("proj1"), iam.WithName("proj1"))
	proj2Group := iam.TestGroup(t, conn, proj2.GetPublicId(), iam.WithDescription("proj2"), iam.WithName("proj2"))
	proj3Group := iam.TestGroup(t, conn, proj3.GetPublicId(), iam.WithDescription("proj3"), iam.WithName("proj3"))
	testcases := []struct {
		name     string
		input    *pbs.ListGroupsRequest
		userFunc func() (*iam.User, auth.Account)
		wantErr  error
		wantIDs  []string
	}{
		{
			name:    "global role grant this only returns in global groups",
			wantErr: nil,
			input: &pbs.ListGroupsRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantIDs: []string{globalGroup.PublicId},
		},
		{
			name: "global role grant this and children returns global and org groups",
			input: &pbs.ListGroupsRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=list,read"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantErr: nil,
			wantIDs: []string{globalGroup.PublicId, org1Group.PublicId, org2Group.PublicId},
		},
		{
			name: "global role grant via managed groups this and children returns org and proj groups",
			input: &pbs.ListGroupsRequest{
				ScopeId:   org1.PublicId,
				Recursive: true,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=group;actions=list,read"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantErr: nil,
			wantIDs: []string{org1Group.PublicId, proj1Group.PublicId},
		},
		{
			name: "global role grant this and descendant returns all groups",
			input: &pbs.ListGroupsRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			wantErr: nil,
			wantIDs: []string{globalGroup.PublicId, org1Group.PublicId, org2Group.PublicId, proj1Group.PublicId, proj2Group.PublicId, proj3Group.PublicId},
		},
		{
			name: "org role grant children IDs only org children",
			input: &pbs.ListGroupsRequest{
				ScopeId:   org2.PublicId,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			wantErr: nil,
			wantIDs: []string{org2Group.PublicId, proj2Group.PublicId, proj3Group.PublicId},
		},
		{
			name: "LDAP org role grant children IDs only org children",
			input: &pbs.ListGroupsRequest{
				ScopeId:   org2.PublicId,
				Recursive: true,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org2.PublicId,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: nil,
			wantIDs: []string{org2Group.PublicId},
		},
		{
			name: "no list permission returns error",
			input: &pbs.ListGroupsRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants: []string{
						fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId),
					},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			wantErr: handlers.ForbiddenError(),
			wantIDs: nil,
		},
		{
			name: "global role scope specific grants only returns granted scopes",
			input: &pbs.ListGroupsRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read,list"},
					GrantScopes: []string{proj1.PublicId, proj2.PublicId, proj3.PublicId},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read,list"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: nil,
			wantIDs: []string{globalGroup.PublicId, proj1Group.PublicId, proj2Group.PublicId, proj3Group.PublicId},
		},
		{
			name: "global role not granted group resources returns error",
			input: &pbs.ListGroupsRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=target;actions=read,list"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			wantErr: handlers.ForbiddenError(),
			wantIDs: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, finalErr := s.ListGroups(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
			var gotIDs []string
			for _, g := range got.Items {
				gotIDs = append(gotIDs, g.GetId())
			}
			require.ElementsMatch(t, tc.wantIDs, gotIDs)
		})
	}
}

func TestGrants_GetGroup(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	org1, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)

	globalGroup := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))
	org1Group := iam.TestGroup(t, conn, org1.GetPublicId(), iam.WithDescription("org1"), iam.WithName("org1"))
	org2Group := iam.TestGroup(t, conn, org2.GetPublicId(), iam.WithDescription("org2"), iam.WithName("org2"))
	proj1Group := iam.TestGroup(t, conn, proj1.GetPublicId(), iam.WithDescription("proj1"), iam.WithName("proj1"))
	proj2Group := iam.TestGroup(t, conn, proj2.GetPublicId(), iam.WithDescription("proj2"), iam.WithName("proj2"))

	testcases := []struct {
		name            string
		userFunc        func() (*iam.User, auth.Account)
		inputWantErrMap map[*pbs.GetGroupRequest]error
	}{
		{
			name: "global role group grant this scope with all permissions",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: nil,
				{Id: org1Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj1Group.PublicId}:  handlers.ForbiddenError(),
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "global role group grant this scope with all permissions",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: nil,
				{Id: org1Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj1Group.PublicId}:  handlers.ForbiddenError(),
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant children scopes with all permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: handlers.ForbiddenError(),
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  handlers.ForbiddenError(),
				{Id: org2Group.PublicId}:   nil,
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant descendant scopes with all permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeDescendants},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: handlers.ForbiddenError(),
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  nil,
				{Id: org2Group.PublicId}:   nil,
				{Id: proj2Group.PublicId}:  nil,
			},
		},
		{
			name: "global role grant this and children scopes with all permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: nil,
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  handlers.ForbiddenError(),
				{Id: org2Group.PublicId}:   nil,
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant this and descendant scopes with all permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: nil,
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  nil,
				{Id: org2Group.PublicId}:   nil,
				{Id: proj2Group.PublicId}:  nil,
			},
		},
		{
			name: "org1 role grant this scope with all permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.GetPublicId(),
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: handlers.ForbiddenError(),
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  handlers.ForbiddenError(),
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "org1 role grant children scope with all permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.GetPublicId(),
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: handlers.ForbiddenError(),
				{Id: org1Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj1Group.PublicId}:  nil,
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "org1 role grant this and children scopes with all permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.GetPublicId(),
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: handlers.ForbiddenError(),
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  nil,
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "proj1 role grant this scope with all permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: proj1.GetPublicId(),
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: handlers.ForbiddenError(),
				{Id: org1Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj1Group.PublicId}:  nil,
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant this and descendant scope with read permissions on specific group",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{fmt.Sprintf("ids=%s;types=group ;actions=read", org1Group.PublicId)},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: handlers.ForbiddenError(),
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  handlers.ForbiddenError(),
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "global role grant this and specific scopes with read permissions on specific group",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants: []string{
						fmt.Sprintf("ids=%s;types=group;actions=read", org1Group.PublicId),
						fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId),
					},
					GrantScopes: []string{org1.PublicId, proj1.PublicId},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: handlers.ForbiddenError(),
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  nil,
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
		{
			name: "union multiple role grant specific resources permissions",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants: []string{
						fmt.Sprintf("ids=%s;types=group;actions=read", globalGroup.PublicId),
					},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: org1.GetPublicId(),
					Grants: []string{
						fmt.Sprintf("ids=%s;types=group;actions=read", org1Group.PublicId),
						fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId),
					},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetGroupRequest]error{
				{Id: globalGroup.PublicId}: nil,
				{Id: org1Group.PublicId}:   nil,
				{Id: proj1Group.PublicId}:  nil,
				{Id: org2Group.PublicId}:   handlers.ForbiddenError(),
				{Id: proj2Group.PublicId}:  handlers.ForbiddenError(),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for input, wantErr := range tc.inputWantErrMap {
				_, err := s.GetGroup(fullGrantAuthCtx, input)
				// not found means expect error
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestGrants_CreateGroup(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)

	org1, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	testcases := []struct {
		name              string
		userFunc          func() (*iam.User, auth.Account)
		canCreateInScopes map[*pbs.CreateGroupRequest]error
	}{
		{
			name: "direct grant all can create all",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			canCreateInScopes: map[*pbs.CreateGroupRequest]error{
				{Item: &pb.Group{ScopeId: globals.GlobalPrefix}}: nil,
				{Item: &pb.Group{ScopeId: org1.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: org2.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: proj1.PublicId}}:       nil,
				{Item: &pb.Group{ScopeId: proj2.PublicId}}:       nil,
				{Item: &pb.Group{ScopeId: proj3.PublicId}}:       nil,
			},
		},
		{
			name: "groups grant all can create all",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			canCreateInScopes: map[*pbs.CreateGroupRequest]error{
				{Item: &pb.Group{ScopeId: globals.GlobalPrefix}}: nil,
				{Item: &pb.Group{ScopeId: org1.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: org2.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: proj1.PublicId}}:       nil,
				{Item: &pb.Group{ScopeId: proj2.PublicId}}:       nil,
				{Item: &pb.Group{ScopeId: proj3.PublicId}}:       nil,
			},
		},
		{
			name: "ldap grant all can create all",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			canCreateInScopes: map[*pbs.CreateGroupRequest]error{
				{Item: &pb.Group{ScopeId: globals.GlobalPrefix}}: nil,
				{Item: &pb.Group{ScopeId: org1.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: org2.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: proj1.PublicId}}:       nil,
				{Item: &pb.Group{ScopeId: proj2.PublicId}}:       nil,
				{Item: &pb.Group{ScopeId: proj3.PublicId}}:       nil,
			},
		},
		{
			name: "oidc grant all can create all",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			canCreateInScopes: map[*pbs.CreateGroupRequest]error{
				{Item: &pb.Group{ScopeId: globals.GlobalPrefix}}: nil,
				{Item: &pb.Group{ScopeId: org1.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: org2.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: proj1.PublicId}}:       nil,
				{Item: &pb.Group{ScopeId: proj2.PublicId}}:       nil,
				{Item: &pb.Group{ScopeId: proj3.PublicId}}:       nil,
			},
		},
		{
			name: "grant children can only create in orgs",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			canCreateInScopes: map[*pbs.CreateGroupRequest]error{
				{Item: &pb.Group{ScopeId: globals.GlobalPrefix}}: handlers.ForbiddenError(),
				{Item: &pb.Group{ScopeId: org1.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: org2.PublicId}}:        nil,
				{Item: &pb.Group{ScopeId: proj1.PublicId}}:       handlers.ForbiddenError(),
				{Item: &pb.Group{ScopeId: proj2.PublicId}}:       handlers.ForbiddenError(),
				{Item: &pb.Group{ScopeId: proj3.PublicId}}:       handlers.ForbiddenError(),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

			for req, wantErr := range tc.canCreateInScopes {
				_, err := s.CreateGroup(fullGrantAuthCtx, req)
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

func TestGrants_DeleteGroup(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)

	org1, proj1 := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	allScopeIds := []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId, proj3.PublicId}
	testcases := []struct {
		name                    string
		userFunc                func() (*iam.User, auth.Account)
		deleteAllowedAtScopeIds []string
	}{
		{
			name: "grant all can delete all",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			deleteAllowedAtScopeIds: allScopeIds,
		},
		{
			name: "grant children can only delete in orgs",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			deleteAllowedAtScopeIds: []string{org1.PublicId, org2.PublicId},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// setup a map to track which scope correlates to a group
			scopeIdGroupMap := map[string]*iam.Group{}
			for _, scp := range allScopeIds {
				g := iam.TestGroup(t, conn, scp)
				scopeIdGroupMap[scp] = g
			}
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for scope, group := range scopeIdGroupMap {
				_, err = s.DeleteGroup(fullGrantAuthCtx, &pbs.DeleteGroupRequest{Id: group.PublicId})
				if !slices.Contains(tc.deleteAllowedAtScopeIds, scope) {
					require.ErrorIs(t, err, handlers.ForbiddenError())
					continue
				}
				require.NoErrorf(t, err, "failed to delete group in scope %s", scope)
			}
		})
	}
}

func TestGrants_UpdateGroup(t *testing.T) {
	testcases := []struct {
		name                        string
		setupScopesResourcesAndUser func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*iam.Group, func() (*iam.User, auth.Account))
		wantErr                     error
	}{
		{
			name: "global_scope_group_good_grant_success",
			setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*iam.Group, func() (*iam.User, auth.Account)) {
				g := iam.TestGroup(t, conn, globals.GlobalPrefix)
				return g, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantErr: nil,
		},
		{
			name: "grant specific scope success",
			setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*iam.Group, func() (*iam.User, auth.Account)) {
				_, proj := iam.TestScopes(t, iamRepo)
				g := iam.TestGroup(t, conn, proj.PublicId)
				return g, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{proj.PublicId},
					},
				})
			},
			wantErr: nil,
		},
		{
			name: "grant specific resource and scope success",
			setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*iam.Group, func() (*iam.User, auth.Account)) {
				_, proj := iam.TestScopes(t, iamRepo)
				g := iam.TestGroup(t, conn, proj.PublicId)
				return g, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;types=group;actions=*", g.PublicId)},
						GrantScopes: []string{proj.PublicId},
					},
				})
			},
			wantErr: nil,
		},
		{
			name: "no grant fails update",
			setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository, kmsCache *kms.Kms) (*iam.Group, func() (*iam.User, auth.Account)) {
				g := iam.TestGroup(t, conn, globals.GlobalPrefix)
				return g, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			wantErr: handlers.ForbiddenError(),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			conn, _ := db.TestSetup(t, "postgres")
			rw := db.New(conn)
			wrap := db.TestWrapper(t)
			iamRepo := iam.TestRepo(t, conn, wrap)
			kmsCache := kms.TestKms(t, conn, wrap)
			atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
			require.NoError(t, err)
			repoFn := func() (*iam.Repository, error) {
				return iamRepo, nil
			}
			s, err := groups.NewService(ctx, repoFn, 1000)
			require.NoError(t, err)
			original, userFunc := tc.setupScopesResourcesAndUser(t, conn, iamRepo, kmsCache)
			user, account := userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.UpdateGroup(fullGrantAuthCtx, &pbs.UpdateGroupRequest{
				Id: original.PublicId,
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: "new-name"},
					Description: &wrapperspb.StringValue{Value: "new-description"},
					Version:     1,
				},
				UpdateMask: &fieldmaskpb.FieldMask{
					Paths: []string{"name", "description"},
				},
			})
			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, uint32(2), got.Item.Version)
			require.True(t, got.Item.UpdatedTime.AsTime().After(original.UpdateTime.AsTime()))
		})
	}
}

func TestGrants_GroupMembership(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)

	org1, _ := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

	globalUsers := []*iam.User{iam.TestUser(t, iamRepo, globals.GlobalPrefix), iam.TestUser(t, iamRepo, globals.GlobalPrefix)}
	org1Users := []*iam.User{iam.TestUser(t, iamRepo, org1.PublicId), iam.TestUser(t, iamRepo, org1.PublicId)}
	org2Users := []*iam.User{iam.TestUser(t, iamRepo, org2.PublicId), iam.TestUser(t, iamRepo, org2.PublicId)}

	type groupGetter interface {
		GetItem() *pb.Group
	}

	type testActionResult struct {
		action  func(context.Context, *iam.Group) (groupGetter, error)
		wantErr error
	}

	testcases := []struct {
		name              string
		userFunc          func() *iam.User
		setupGroupAndRole func(t *testing.T) (*iam.Group, func() (*iam.User, auth.Account))
		// collection of actions to be executed in the tests in order, *iam.Group returned from each action which
		// gets passed to the next action as parameter to preserve information such as `version` increments
		actions []testActionResult
	}{
		{
			name: "all actions valid grant success",

			setupGroupAndRole: func(t *testing.T) (*iam.Group, func() (*iam.User, auth.Account)) {
				group := iam.TestGroup(t, conn, globals.GlobalPrefix)
				return group, iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			actions: []testActionResult{
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.AddGroupMembers(authCtx, &pbs.AddGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org1Users),
						})
						return out, err
					},
					wantErr: nil,
				},
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.SetGroupMembers(authCtx, &pbs.SetGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(globalUsers),
						})
						return out, err
					},
					wantErr: nil,
				},
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.RemoveGroupMembers(authCtx, &pbs.RemoveGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(globalUsers),
						})
						return out, err
					},
					wantErr: nil,
				},
			},
		},
		{
			name: "only add and set allowed fail to remove",
			setupGroupAndRole: func(t *testing.T) (*iam.Group, func() (*iam.User, auth.Account)) {
				group := iam.TestGroup(t, conn, org1.PublicId)
				return group, iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=*;actions=add-members"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=*;actions=set-members"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			actions: []testActionResult{
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.AddGroupMembers(authCtx, &pbs.AddGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org1Users),
						})
						return out, err
					},
					wantErr: nil,
				},
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.SetGroupMembers(authCtx, &pbs.SetGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org1Users),
						})
						return out, err
					},
					wantErr: nil,
				},
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.RemoveGroupMembers(authCtx, &pbs.RemoveGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org1Users),
						})
						return out, err
					},
					wantErr: handlers.ForbiddenError(),
				},
			},
		},
		{
			name: "add_member_valid_specific_grant_success",
			setupGroupAndRole: func(t *testing.T) (*iam.Group, func() (*iam.User, auth.Account)) {
				group := iam.TestGroup(t, conn, org2.PublicId)
				return group, iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{fmt.Sprintf("ids=%s;types=group;actions=add-members", group.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			actions: []testActionResult{
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.AddGroupMembers(authCtx, &pbs.AddGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org2Users),
						})
						return out, err
					},
					wantErr: nil,
				},
			},
		},
		{
			name: "remove_member_valid_specific_grant_success",
			setupGroupAndRole: func(t *testing.T) (*iam.Group, func() (*iam.User, auth.Account)) {
				group := iam.TestGroup(t, conn, proj2.PublicId)
				iam.TestGroupMember(t, conn, group.PublicId, org2Users[0].PublicId)
				iam.TestGroupMember(t, conn, group.PublicId, org2Users[1].PublicId)
				return group, iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;types=group;actions=remove-members", group.PublicId)},
						GrantScopes: []string{proj2.PublicId},
					},
				})
			},
			actions: []testActionResult{
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.RemoveGroupMembers(authCtx, &pbs.RemoveGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org2Users),
						})
						return out, err
					},
					wantErr: nil,
				},
			},
		},
		{
			name: "cross_scope_add_member_valid_specific_grant_success",
			setupGroupAndRole: func(t *testing.T) (*iam.Group, func() (*iam.User, auth.Account)) {
				group := iam.TestGroup(t, conn, proj3.PublicId)
				return group, iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;types=group;actions=add-members", group.PublicId)},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})
			},
			actions: []testActionResult{
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						users := userIDs(org1Users)
						users = append(users, userIDs(org2Users)...)
						out, err := s.AddGroupMembers(authCtx, &pbs.AddGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: users,
						})
						return out, err
					},
					wantErr: nil,
				},
			},
		},
		{
			name: "add_member_with_valid_grant_string_invalid_scope_forbidden_error",
			setupGroupAndRole: func(t *testing.T) (*iam.Group, func() (*iam.User, auth.Account)) {
				group := iam.TestGroup(t, conn, org2.PublicId)
				return group, iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			actions: []testActionResult{
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.AddGroupMembers(authCtx, &pbs.AddGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org2Users),
						})
						return out, err
					},
					wantErr: handlers.ForbiddenError(),
				},
			},
		},
		{
			name: "multiple_grants_success",
			setupGroupAndRole: func(t *testing.T) (*iam.Group, func() (*iam.User, auth.Account)) {
				group := iam.TestGroup(t, conn, proj2.PublicId)
				return group, iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{fmt.Sprintf("ids=%s;types=group;actions=add-members", group.PublicId)},
						GrantScopes: []string{proj2.PublicId},
					},
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{fmt.Sprintf("ids=%s;types=group;actions=set-members", group.PublicId)},
						GrantScopes: []string{proj2.PublicId},
					},
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{fmt.Sprintf("ids=%s;types=group;actions=remove-members", group.PublicId)},
						GrantScopes: []string{proj2.PublicId},
					},
				})
			},
			actions: []testActionResult{
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.AddGroupMembers(authCtx, &pbs.AddGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org2Users),
						})
						return out, err
					},
					wantErr: nil,
				},
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.SetGroupMembers(authCtx, &pbs.SetGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org2Users),
						})
						return out, err
					},
					wantErr: nil,
				},
				{
					action: func(authCtx context.Context, g *iam.Group) (groupGetter, error) {
						out, err := s.RemoveGroupMembers(authCtx, &pbs.RemoveGroupMembersRequest{
							Id:        g.PublicId,
							Version:   g.Version,
							MemberIds: userIDs(org2Users),
						})
						return out, err
					},
					wantErr: nil,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			group, userFn := tc.setupGroupAndRole(t)
			user, account := userFn()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for _, act := range tc.actions {
				out, err := act.action(fullGrantAuthCtx, group)
				if act.wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, act.wantErr)
					continue
				}
				require.NoError(t, err)
				// set version for future updates
				group.Version = out.GetItem().Version
			}
		})
	}
}

func TestOutputFields_ListGroups(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	globalGroup := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))

	org, proj := iam.TestScopes(t, iamRepo)
	orgGroup := iam.TestGroup(t, conn, org.PublicId, iam.WithDescription("org"), iam.WithName("org"))
	projGroup := iam.TestGroup(t, conn, proj.PublicId, iam.WithDescription("proj"), iam.WithName("proj"))

	globalUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	orgUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	projectUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix)

	_ = iam.TestGroupMember(t, conn, globalGroup.PublicId, globalUser.PublicId)
	_ = iam.TestGroupMember(t, conn, orgGroup.PublicId, orgUser.PublicId)
	_ = iam.TestGroupMember(t, conn, projGroup.PublicId, projectUser.PublicId)
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name     string
		userFunc func() (*iam.User, auth.Account)
		// keys are the group IDs | this also means 'id' is required in the outputfields for assertions to work properly
		expectOutfields map[string][]string
	}{
		{
			name: "grants name, version, description",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,name,description"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			expectOutfields: map[string][]string{
				globalGroup.PublicId: {globals.IdField, globals.NameField, globals.DescriptionField},
				orgGroup.PublicId:    {globals.IdField, globals.NameField, globals.DescriptionField},
				projGroup.PublicId:   {globals.IdField, globals.NameField, globals.DescriptionField},
			},
		},
		{
			name: "grants scope, scopeId, authorized_actions",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,scope,scope_id,authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			expectOutfields: map[string][]string{
				globalGroup.PublicId: {globals.IdField, globals.ScopeField, globals.ScopeIdField, globals.AuthorizedActionsField},
				orgGroup.PublicId:    {globals.IdField, globals.ScopeField, globals.ScopeIdField, globals.AuthorizedActionsField},
				projGroup.PublicId:   {globals.IdField, globals.ScopeField, globals.ScopeIdField, globals.AuthorizedActionsField},
			},
		},
		{
			name: "grants update_time, create_time",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,updated_time,created_time,members,member_ids"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
				},
			}),
			expectOutfields: map[string][]string{
				globalGroup.PublicId: {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
				orgGroup.PublicId:    {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
				projGroup.PublicId:   {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
		},
		{
			name: "different output_fields for different scope",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,scope,scope_id,created_time,updated_time"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
				{
					RoleScopeId: proj.PublicId,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,authorized_actions"},
					GrantScopes: []string{proj.PublicId},
				},
			}),
			expectOutfields: map[string][]string{
				globalGroup.PublicId: {globals.IdField, globals.NameField, globals.DescriptionField},
				orgGroup.PublicId:    {globals.IdField, globals.ScopeField, globals.ScopeIdField, globals.CreatedTimeField, globals.UpdatedTimeField},
				projGroup.PublicId:   {globals.IdField, globals.AuthorizedActionsField},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			out, err := s.ListGroups(fullGrantAuthCtx, &pbs.ListGroupsRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			})
			require.NoError(t, err)
			for _, item := range out.Items {
				handlers.TestAssertOutputFields(t, item, tc.expectOutfields[item.Id])
			}
		})
	}
}

func TestOutputFields_GetGroup(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	globalGroupWithMember := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))
	u := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	_ = iam.TestGroupMember(t, conn, globalGroupWithMember.PublicId, u.PublicId)
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)

	testcases := []struct {
		name            string
		userFunc        func() (*iam.User, auth.Account)
		expectOutfields []string
	}{
		{
			name: "grants name and description",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read;output_fields=name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.NameField, globals.DescriptionField},
		},
		{
			name: "grants scope and scopeId",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read;output_fields=scope,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.ScopeField, globals.ScopeIdField},
		},
		{
			name: "grants update_time and create_time",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read;output_fields=updated_time,created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
		},
		{
			name: "grants id, authorized_actions, version",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read;output_fields=id,authorized_actions,version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.AuthorizedActionsField, globals.VersionField},
		},
		{
			name: "grants members, member_id",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read;output_fields=members,member_ids"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.MembersField, globals.MemberIdsField},
		},
		{
			name: "composite grants id, authorized_actions, member_ids",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read;output_fields=member_ids"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read;output_fields=authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.MemberIdsField, globals.AuthorizedActionsField},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			out, err := s.GetGroup(fullGrantAuthCtx, &pbs.GetGroupRequest{Id: globalGroupWithMember.PublicId})
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
		})
	}
}

func TestOutputFields_CreateGroup(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	genUuid := func() string {
		u, _ := uuid.GenerateUUID()
		return u
	}

	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name            string
		userFunc        func() (*iam.User, auth.Account)
		input           *pbs.CreateGroupRequest
		expectOutfields []string
	}{
		{
			name: "grants name and description",
			input: &pbs.CreateGroupRequest{
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: genUuid()},
					Description: &wrapperspb.StringValue{Value: genUuid()},
					ScopeId:     globals.GlobalPrefix,
				},
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.NameField, globals.DescriptionField},
		},
		{
			name: "grants scope and scopeId",
			input: &pbs.CreateGroupRequest{
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: genUuid()},
					Description: &wrapperspb.StringValue{Value: genUuid()},
					ScopeId:     globals.GlobalPrefix,
				},
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.ScopeField, globals.ScopeIdField},
		},
		{
			name: "grants update_time and create_time",
			input: &pbs.CreateGroupRequest{
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: genUuid()},
					Description: &wrapperspb.StringValue{Value: genUuid()},
					ScopeId:     globals.GlobalPrefix,
				},
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=updated_time,created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
		},
		{
			name: "grants id, authorized_actions, version",
			input: &pbs.CreateGroupRequest{
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: genUuid()},
					Description: &wrapperspb.StringValue{Value: genUuid()},
					ScopeId:     globals.GlobalPrefix,
				},
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,authorized_actions,version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.AuthorizedActionsField, globals.VersionField},
		},
		{
			name: "composite grants all fields",
			input: &pbs.CreateGroupRequest{
				Item: &pb.Group{
					Name:        &wrapperspb.StringValue{Value: genUuid()},
					Description: &wrapperspb.StringValue{Value: genUuid()},
					ScopeId:     globals.GlobalPrefix,
				},
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{
				globals.IdField,
				globals.ScopeField,
				globals.ScopeIdField,
				globals.NameField,
				globals.DescriptionField,
				globals.CreatedTimeField,
				globals.AuthorizedActionsField,
				globals.VersionField,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			out, err := s.CreateGroup(fullGrantAuthCtx, tc.input)
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
		})
	}
}

func TestOutputFields_UpdateGroup(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	// this can be used across test cases because we're only testing for output fields, not the update behaviors
	inputFunc := func(t *testing.T) *pbs.UpdateGroupRequest {
		name, _ := uuid.GenerateUUID()
		desc, _ := uuid.GenerateUUID()
		globalGroupWithMember := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))
		u := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
		_ = iam.TestGroupMember(t, conn, globalGroupWithMember.PublicId, u.PublicId)
		return &pbs.UpdateGroupRequest{
			Id: globalGroupWithMember.PublicId,
			Item: &pb.Group{
				Name:        &wrapperspb.StringValue{Value: name},
				Description: &wrapperspb.StringValue{Value: desc},
				Version:     globalGroupWithMember.Version,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "description"},
			},
		}
	}

	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name            string
		userFunc        func() (*iam.User, auth.Account)
		expectOutfields []string
	}{
		{
			name: "grants name and description",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.NameField, globals.DescriptionField},
		},
		{
			name: "grants scope and scopeId",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.ScopeField, globals.ScopeIdField},
		},
		{
			name: "grants update_time and create_time",

			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=updated_time,created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
		},
		{
			name: "grants id, authorized_actions, version",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,authorized_actions,version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.AuthorizedActionsField, globals.VersionField},
		},
		{
			name: "composite grants all fields",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{
				globals.IdField,
				globals.ScopeField,
				globals.ScopeIdField,
				globals.NameField,
				globals.DescriptionField,
				globals.CreatedTimeField,
				globals.AuthorizedActionsField,
				globals.VersionField,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			out, err := s.UpdateGroup(fullGrantAuthCtx, inputFunc(t))
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
		})
	}
}

func TestOutputFields_AddGroupMembers(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	// this can be used across test cases because we're only testing for output fields, not the update behaviors
	inputFunc := func(t *testing.T) *pbs.AddGroupMembersRequest {
		name, _ := uuid.GenerateUUID()
		desc, _ := uuid.GenerateUUID()
		globalGroupWithMember := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription(desc), iam.WithName(name))
		u := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
		return &pbs.AddGroupMembersRequest{
			Id:        globalGroupWithMember.PublicId,
			Version:   globalGroupWithMember.Version,
			MemberIds: []string{u.PublicId},
		}
	}
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name            string
		userFunc        func() (*iam.User, auth.Account)
		expectOutfields []string
	}{
		{
			name: "grants name and description",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.NameField, globals.DescriptionField},
		},
		{
			name: "grants scope and scopeId",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.ScopeField, globals.ScopeIdField},
		},
		{
			name: "grants update_time and create_time",

			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=updated_time,created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
		},
		{
			name: "grants id, authorized_actions, version",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,authorized_actions,version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.AuthorizedActionsField, globals.VersionField},
		},
		{
			name: "composite grants all fields",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{
				globals.IdField,
				globals.ScopeField,
				globals.ScopeIdField,
				globals.NameField,
				globals.DescriptionField,
				globals.CreatedTimeField,
				globals.AuthorizedActionsField,
				globals.VersionField,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			out, err := s.AddGroupMembers(fullGrantAuthCtx, inputFunc(t))
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
		})
	}
}

func TestOutputFields_SetGroupMembers(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	// this can be used across test cases because we're only testing for output fields, not the update behaviors
	inputFunc := func(t *testing.T) *pbs.SetGroupMembersRequest {
		name, _ := uuid.GenerateUUID()
		desc, _ := uuid.GenerateUUID()
		globalGroupWithMember := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription(desc), iam.WithName(name))
		u := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
		return &pbs.SetGroupMembersRequest{
			Id:        globalGroupWithMember.PublicId,
			Version:   globalGroupWithMember.Version,
			MemberIds: []string{u.PublicId},
		}
	}
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name            string
		userFunc        func() (*iam.User, auth.Account)
		expectOutfields []string
	}{
		{
			name: "grants name and description",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.NameField, globals.DescriptionField},
		},
		{
			name: "grants scope and scopeId",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.ScopeField, globals.ScopeIdField},
		},
		{
			name: "grants update_time and create_time",

			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=updated_time,created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
		},
		{
			name: "grants id, authorized_actions, version",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,authorized_actions,version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.AuthorizedActionsField, globals.VersionField},
		},
		{
			name: "composite grants all fields",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{
				globals.IdField,
				globals.ScopeField,
				globals.ScopeIdField,
				globals.NameField,
				globals.DescriptionField,
				globals.CreatedTimeField,
				globals.AuthorizedActionsField,
				globals.VersionField,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			out, err := s.SetGroupMembers(fullGrantAuthCtx, inputFunc(t))
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
		})
	}
}

func TestOutputFields_RemoveGroupMembers(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	// this can be used across test cases because we're only testing for output fields, not the update behaviors
	inputFunc := func(t *testing.T) *pbs.RemoveGroupMembersRequest {
		name, _ := uuid.GenerateUUID()
		desc, _ := uuid.GenerateUUID()
		globalGroupWithMember := iam.TestGroup(t, conn, globals.GlobalPrefix, iam.WithDescription(desc), iam.WithName(name))
		// create 2 users and remove one so the tests can differentiate between the group without members vs. having no access to read members
		u1 := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
		u2 := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
		_ = iam.TestGroupMember(t, conn, globalGroupWithMember.PublicId, u1.PublicId)
		_ = iam.TestGroupMember(t, conn, globalGroupWithMember.PublicId, u2.PublicId)
		return &pbs.RemoveGroupMembersRequest{
			Id:        globalGroupWithMember.PublicId,
			Version:   globalGroupWithMember.Version,
			MemberIds: []string{u2.PublicId},
		}
	}
	s, err := groups.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name            string
		userFunc        func() (*iam.User, auth.Account)
		expectOutfields []string
	}{
		{
			name: "grants name and description",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name,description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.NameField, globals.DescriptionField},
		},
		{
			name: "grants scope and scopeId",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.ScopeField, globals.ScopeIdField},
		},
		{
			name: "grants update_time and create_time",

			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=updated_time,created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
		},
		{
			name: "grants id, authorized_actions, version",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id,authorized_actions,version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.AuthorizedActionsField, globals.VersionField},
		},
		{
			name: "composite grants all fields",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=scope_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=name"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=description"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=created_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=authorized_actions"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=*;output_fields=version"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{
				globals.IdField,
				globals.ScopeField,
				globals.ScopeIdField,
				globals.NameField,
				globals.DescriptionField,
				globals.CreatedTimeField,
				globals.AuthorizedActionsField,
				globals.VersionField,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			out, err := s.RemoveGroupMembers(fullGrantAuthCtx, inputFunc(t))
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
		})
	}
}

func userIDs(users []*iam.User) []string {
	result := make([]string, len(users))
	for i, u := range users {
		result[i] = u.PublicId
	}
	return result
}
