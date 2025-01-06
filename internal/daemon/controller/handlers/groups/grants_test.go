// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package groups_test

import (
	"context"
	"fmt"
	"slices"
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
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type roleRequest struct {
	roleScopeID  string
	grantStrings []string
	grantScopes  []string
}

// testGenAuthTokenCtx creates an auth.VerifierContext which contains a valid auth token
// for a user which is associated with roles in the roles parameter
// this function creates an authMethod, account, user at global scope
func testGenAuthTokenCtx(t *testing.T,
	ctx context.Context,
	conn *db.DB,
	wrap wrapping.Wrapper,
	iamRepo *iam.Repository,
	roles []roleRequest,
) context.Context {
	t.Helper()
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return atRepo, nil
	}

	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	authMethod := password.TestAuthMethods(t, conn, globals.GlobalPrefix, 1)[0]

	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), uuid.NewString())
	user := iam.TestUser(t, iamRepo, globals.GlobalPrefix, iam.WithAccountIds(acct.GetPublicId()))
	for _, r := range roles {
		role := iam.TestRoleWithGrants(t, conn, r.roleScopeID, r.grantScopes, r.grantStrings)
		_ = iam.TestUserRole(t, conn, role.PublicId, user.PublicId)
	}
	fullGrantToken, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
	require.NoError(t, err)
	fullGrantAuthCtx := auth.NewVerifierContext(requests.NewRequestContext(ctx, requests.WithUserId(user.GetPublicId())),
		iamRepoFn, atRepoFn, serversRepoFn, kmsCache, &authpb.RequestInfo{
			PublicId:    fullGrantToken.PublicId,
			Token:       fullGrantToken.GetToken(),
			TokenFormat: uint32(auth.AuthTokenTypeBearer),
		})
	return fullGrantAuthCtx
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
						grantStrings: []string{"ids=*;type=group;actions=list,read"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: []string{globalGroup.PublicId, org1Group.PublicId, org2Group.PublicId},
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
			{
				name: "global role scope specific grants only returns granted scopes",
				input: &pbs.ListGroupsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"ids=*;type=group;actions=read,list"},
						grantScopes:  []string{proj1.PublicId, proj2.PublicId, proj3.PublicId},
					},
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"ids=*;type=group;actions=read,list"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: nil,
				wantIDs: []string{globalGroup.PublicId, proj1Group.PublicId, proj2Group.PublicId, proj3Group.PublicId},
			},
			{
				name: "global role not granted group resources returns error",
				input: &pbs.ListGroupsRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"ids=*;type=target;actions=read,list"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: handlers.ForbiddenError(),
				wantIDs: nil,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				fullGrantAuthCtx := testGenAuthTokenCtx(t, ctx, conn, wrap, iamRepo, tc.rolesToCreate)
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
	})

	t.Run("Get", func(t *testing.T) {
		testcases := []struct {
			name            string
			rolesToCreate   []roleRequest
			inputWantErrMap map[*pbs.GetGroupRequest]error
		}{
			{
				name: "global role grant this scope with all permissions",
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeChildren},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeDescendants},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  org1.GetPublicId(),
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  org1.GetPublicId(),
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeChildren},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  org1.GetPublicId(),
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  proj1.GetPublicId(),
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{fmt.Sprintf("ids=%s;types=group ;actions=read", org1Group.PublicId)},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID: globals.GlobalPrefix,
						grantStrings: []string{
							fmt.Sprintf("ids=%s;types=group;actions=read", org1Group.PublicId),
							fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId),
						},
						grantScopes: []string{org1.PublicId, proj1.PublicId},
					},
				},
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
				rolesToCreate: []roleRequest{
					{
						roleScopeID: globals.GlobalPrefix,
						grantStrings: []string{
							fmt.Sprintf("ids=%s;types=group;actions=read", globalGroup.PublicId),
						},
						grantScopes: []string{globals.GrantScopeThis},
					},
					{
						roleScopeID: org1.GetPublicId(),
						grantStrings: []string{
							fmt.Sprintf("ids=%s;types=group;actions=read", org1Group.PublicId),
							fmt.Sprintf("ids=%s;types=group;actions=read", proj1Group.PublicId),
						},
						grantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
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
				fullGrantAuthCtx := testGenAuthTokenCtx(t, ctx, conn, wrap, iamRepo, tc.rolesToCreate)
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
	})
}

// TestWriteActions tests write actions to assert that grants are being applied properly
//
//	[create, update, delete]
//	Role - which scope the role is created in
//			- global level
//			- org level
//			- project level
//	Grant - what IAM grant scope is set for the permission
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
func TestWrites(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		wrap := db.TestWrapper(t)
		iamRepo := iam.TestRepo(t, conn, wrap)
		repoFn := func() (*iam.Repository, error) {
			return iamRepo, nil
		}
		s, err := groups.NewService(ctx, repoFn, 1000)
		require.NoError(t, err)

		org1, proj1 := iam.TestScopes(t, iamRepo)
		org2, proj2 := iam.TestScopes(t, iamRepo)
		proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

		allScopeIDs := []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId, proj3.PublicId}
		testcases := []struct {
			name              string
			roles             []roleRequest
			canCreateInScopes []string
		}{
			{
				name: "grant all can create all",
				roles: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				canCreateInScopes: allScopeIDs,
			},
			{
				name: "grant children can only create in orgs",
				roles: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				canCreateInScopes: []string{org1.PublicId, org2.PublicId},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				fullGrantAuthCtx := testGenAuthTokenCtx(t, ctx, conn, wrap, iamRepo, tc.roles)

				for _, scope := range allScopeIDs {
					name := uuid.NewString()
					got, err := s.CreateGroup(fullGrantAuthCtx, &pbs.CreateGroupRequest{
						Item: &pb.Group{
							ScopeId:     scope,
							Name:        &wrapperspb.StringValue{Value: name},
							Description: &wrapperspb.StringValue{Value: name},
						},
					})
					if !slices.Contains(tc.canCreateInScopes, scope) {
						require.ErrorIs(t, err, handlers.ForbiddenError())
						continue
					}
					require.NoErrorf(t, err, "failed to create group in scope %s", scope)
					g, _, err := iamRepo.LookupGroup(ctx, got.Item.Id)
					require.NoError(t, err)
					require.Equal(t, name, g.Name)
				}
			})
		}
	})
	t.Run("delete", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		wrap := db.TestWrapper(t)
		iamRepo := iam.TestRepo(t, conn, wrap)
		repoFn := func() (*iam.Repository, error) {
			return iamRepo, nil
		}
		s, err := groups.NewService(ctx, repoFn, 1000)
		require.NoError(t, err)

		org1, proj1 := iam.TestScopes(t, iamRepo)
		org2, proj2 := iam.TestScopes(t, iamRepo)
		proj3 := iam.TestProject(t, iamRepo, org2.GetPublicId())

		allScopeIDs := []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId, proj3.PublicId}
		testcases := []struct {
			name                    string
			roles                   []roleRequest
			deleteAllowedAtScopeIDs []string
		}{
			{
				name: "grant all can delete all",
				roles: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				deleteAllowedAtScopeIDs: allScopeIDs,
			},
			{
				name: "grant children can only delete in orgs",
				roles: []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				deleteAllowedAtScopeIDs: []string{org1.PublicId, org2.PublicId},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				// setup a map to track which scope correlates to a group
				scopeIdGroupMap := map[string]*iam.Group{}
				for _, scp := range allScopeIDs {
					g := iam.TestGroup(t, conn, scp)
					scopeIdGroupMap[scp] = g
				}
				fullGrantAuthCtx := testGenAuthTokenCtx(t, ctx, conn, wrap, iamRepo, tc.roles)
				for scope, group := range scopeIdGroupMap {
					_, err = s.DeleteGroup(fullGrantAuthCtx, &pbs.DeleteGroupRequest{Id: group.PublicId})
					if !slices.Contains(tc.deleteAllowedAtScopeIDs, scope) {
						require.ErrorIs(t, err, handlers.ForbiddenError())
						continue
					}
					require.NoErrorf(t, err, "failed to delete group in scope %s", scope)
				}
			})
		}
	})

	t.Run("update", func(t *testing.T) {
		testcases := []struct {
			name                      string
			setupScopesResourcesRoles func(t *testing.T, conn *db.DB, iamRepo *iam.Repository) (*iam.Group, []roleRequest)
			wantErr                   error
		}{
			{
				name: "global_scope_group_good_grant_success",
				setupScopesResourcesRoles: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository) (*iam.Group, []roleRequest) {
					g := iam.TestGroup(t, conn, globals.GlobalPrefix)
					roles := []roleRequest{
						{
							roleScopeID:  globals.GlobalPrefix,
							grantStrings: []string{"id=*;type=*;actions=*"},
							grantScopes:  []string{globals.GrantScopeThis},
						},
					}
					return g, roles
				},
				wantErr: nil,
			},
			{
				name: "grant specific scope success",
				setupScopesResourcesRoles: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository) (*iam.Group, []roleRequest) {
					_, proj := iam.TestScopes(t, iamRepo)
					g := iam.TestGroup(t, conn, proj.PublicId)
					roles := []roleRequest{
						{
							roleScopeID:  globals.GlobalPrefix,
							grantStrings: []string{"ids=*;type=*;actions=*"},
							grantScopes:  []string{proj.PublicId},
						},
					}
					return g, roles
				},
				wantErr: nil,
			},
			{
				name: "grant specific resource and scope success",
				setupScopesResourcesRoles: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository) (*iam.Group, []roleRequest) {
					_, proj := iam.TestScopes(t, iamRepo)
					g := iam.TestGroup(t, conn, proj.PublicId)
					roles := []roleRequest{
						{
							roleScopeID:  globals.GlobalPrefix,
							grantStrings: []string{fmt.Sprintf("ids=%s;types=group;actions=*", g.PublicId)},
							grantScopes:  []string{proj.PublicId},
						},
					}
					return g, roles
				},
				wantErr: nil,
			},
			{
				name: "no grant fails update",
				setupScopesResourcesRoles: func(t *testing.T, conn *db.DB, iamRepo *iam.Repository) (*iam.Group, []roleRequest) {
					g := iam.TestGroup(t, conn, globals.GlobalPrefix)
					roles := []roleRequest{
						{
							roleScopeID:  globals.GlobalPrefix,
							grantStrings: []string{"id=*;type=*;actions=*"},
							grantScopes:  []string{globals.GrantScopeChildren},
						},
					}
					return g, roles
				},
				wantErr: handlers.ForbiddenError(),
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				conn, _ := db.TestSetup(t, "postgres")
				wrap := db.TestWrapper(t)
				iamRepo := iam.TestRepo(t, conn, wrap)
				repoFn := func() (*iam.Repository, error) {
					return iamRepo, nil
				}
				s, err := groups.NewService(ctx, repoFn, 1000)
				require.NoError(t, err)

				original, roles := tc.setupScopesResourcesRoles(t, conn, iamRepo)
				fullGrantAuthCtx := testGenAuthTokenCtx(t, ctx, conn, wrap, iamRepo, roles)

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
	})
}

// TestGroupMember tests actions performed on the group-members (child-resources)
func TestGroupMember(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
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
		setupGroupAndRole func(t *testing.T) (*iam.Group, []roleRequest)
		// collection of actions to be executed in the tests in order
		actions []testActionResult
	}{
		{
			name: "all actions valid grant success",
			setupGroupAndRole: func(t *testing.T) (*iam.Group, []roleRequest) {
				group := iam.TestGroup(t, conn, globals.GlobalPrefix)
				return group, []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				}
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
			setupGroupAndRole: func(t *testing.T) (*iam.Group, []roleRequest) {
				group := iam.TestGroup(t, conn, org1.PublicId)
				return group, []roleRequest{
					{
						roleScopeID:  org1.PublicId,
						grantStrings: []string{"id=*;type=*;actions=add-members"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
					{
						roleScopeID:  org1.PublicId,
						grantStrings: []string{"id=*;type=*;actions=set-members"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				}
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
			setupGroupAndRole: func(t *testing.T) (*iam.Group, []roleRequest) {
				group := iam.TestGroup(t, conn, org2.PublicId)
				return group, []roleRequest{
					{
						roleScopeID:  org2.PublicId,
						grantStrings: []string{fmt.Sprintf("id=%s;types=group;actions=add-members", group.PublicId)},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				}
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
			setupGroupAndRole: func(t *testing.T) (*iam.Group, []roleRequest) {
				group := iam.TestGroup(t, conn, proj2.PublicId)
				iam.TestGroupMember(t, conn, group.PublicId, org2Users[0].PublicId)
				iam.TestGroupMember(t, conn, group.PublicId, org2Users[1].PublicId)
				return group, []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{fmt.Sprintf("id=%s;types=group;actions=remove-members", group.PublicId)},
						grantScopes:  []string{proj2.PublicId},
					},
				}
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
			setupGroupAndRole: func(t *testing.T) (*iam.Group, []roleRequest) {
				group := iam.TestGroup(t, conn, proj3.PublicId)
				return group, []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{fmt.Sprintf("id=%s;types=group;actions=add-members", group.PublicId)},
						grantScopes:  []string{globals.GrantScopeDescendants},
					},
				}
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
			setupGroupAndRole: func(t *testing.T) (*iam.Group, []roleRequest) {
				group := iam.TestGroup(t, conn, org2.PublicId)
				return group, []roleRequest{
					{
						roleScopeID:  globals.GlobalPrefix,
						grantStrings: []string{"id=*;type=*;actions=*"},
						grantScopes:  []string{globals.GrantScopeThis},
					},
				}
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
			setupGroupAndRole: func(t *testing.T) (*iam.Group, []roleRequest) {
				group := iam.TestGroup(t, conn, proj2.PublicId)
				return group, []roleRequest{
					{
						roleScopeID:  proj2.PublicId,
						grantStrings: []string{fmt.Sprintf("id=%s;types=group;actions=add-members", group.PublicId)},
						grantScopes:  []string{proj2.PublicId},
					},
					{
						roleScopeID:  proj2.PublicId,
						grantStrings: []string{fmt.Sprintf("id=%s;types=group;actions=set-members", group.PublicId)},
						grantScopes:  []string{proj2.PublicId},
					},
					{
						roleScopeID:  proj2.PublicId,
						grantStrings: []string{fmt.Sprintf("id=%s;types=group;actions=remove-members", group.PublicId)},
						grantScopes:  []string{proj2.PublicId},
					},
				}
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
			group, roleReqs := tc.setupGroupAndRole(t)
			fullGrantAuthCtx := testGenAuthTokenCtx(t, ctx, conn, wrap, iamRepo, roleReqs)
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

func userIDs(users []*iam.User) []string {
	result := make([]string, len(users))
	for i, u := range users {
		result[i] = u.PublicId
	}
	return result
}
