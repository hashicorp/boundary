// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/users"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(context.Background(), rw, rw, kmsCache)
	}
	s, err := users.NewService(ctx, repoFn, aliasRepoFn, 1000)
	require.NoError(t, err)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org1, _ := iam.TestScopes(t, iamRepo)
	org2, _ := iam.TestScopes(t, iamRepo)

	globalUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix, iam.WithDescription("global"), iam.WithName("global"))
	org1User1 := iam.TestUser(t, iamRepo, org1.GetPublicId(), iam.WithDescription("org1"), iam.WithName("org1"))
	org2User1 := iam.TestUser(t, iamRepo, org2.GetPublicId(), iam.WithDescription("org2-1"), iam.WithName("org2-1"))
	org2User2 := iam.TestUser(t, iamRepo, org2.GetPublicId(), iam.WithDescription("org2-2"), iam.WithName("org2-2"))

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.ListUsersRequest
			userFunc func() (*iam.User, auth.Account)
			// set this flag when the listing user has permission to list global
			// AND the test attempts to list users at global scope
			// users which gets created as a part of token generation
			includeTestUsers bool
			wantErr          error
			wantIDs          []string
		}{
			{
				name: "global role grant this and children recursive list at global returns global and org users",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				includeTestUsers: true,
				wantErr:          nil,
				wantIDs: []string{
					globals.AnyAuthenticatedUserId,
					globals.AnonymousUserId,
					globals.RecoveryUserId,
					globalUser.PublicId,
					org1User1.PublicId,
					org2User1.PublicId,
					org2User2.PublicId,
				},
			},
			{
				name: "org role grant this and children recursive list at org returns org user",
				input: &pbs.ListUsersRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				includeTestUsers: false,
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					org2User1.PublicId,
					org2User2.PublicId,
				},
			},
			{
				name: "global role grant children recursive list at org returns org user",
				input: &pbs.ListUsersRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				includeTestUsers: false,
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					org2User1.PublicId,
					org2User2.PublicId,
				},
			},
			{
				name: "global role grant children recursive list at global returns all org users",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				includeTestUsers: false,
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					org1User1.PublicId,
					org2User1.PublicId,
					org2User2.PublicId,
				},
			},
			{
				name: "org1 role grant this recursive list at global returns org1 users",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				includeTestUsers: false,
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					org1User1.PublicId,
				},
			},
			{
				name: "individual org grant this recursive list at global returns org user",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				includeTestUsers: false,
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					org1User1.PublicId,
					org2User1.PublicId,
					org2User2.PublicId,
				},
			},
			{
				name: "global role grant this recursive list at org returns no user",
				input: &pbs.ListUsersRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				includeTestUsers: false,
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{},
			},
			{
				name: "global role grant this recursive list at global returns only global user",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				includeTestUsers: true,
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{
					globals.AnyAuthenticatedUserId,
					globals.AnonymousUserId,
					globals.RecoveryUserId,
					globalUser.PublicId,
				},
			},
			{
				name: "global role grant children non-recursive list at global returns forbidden error",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: false,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				wantIDs: nil,
			},
			{
				name: "org role grant children non-recursive list at global returns forbidden error",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: false,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"ids=*;type=user;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				wantIDs: nil,
			},
			{
				name: "no grant recursive list returns forbidden error",
				input: &pbs.ListUsersRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{}),
				wantErr:  handlers.ForbiddenError(),
				wantIDs:  nil,
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				t.Cleanup(func() {
					// deleting user to keep assertions clean since we're listing users over and over
					_, _ = iamRepo.DeleteUser(ctx, tok.IamUserId)
				})
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListUsers(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				var gotIDs []string
				if tc.includeTestUsers {
					tc.wantIDs = append(tc.wantIDs, tok.IamUserId)
				}
				for _, g := range got.Items {
					gotIDs = append(gotIDs, g.GetId())
				}
				require.ElementsMatch(t, tc.wantIDs, gotIDs)
			})
		}
	})
}

func TestGrants_ListResolvableAliases(t *testing.T) {
	ctx := t.Context()
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
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	// delete all default roles because they come with list-resolvable-aliases permissions
	_, err = sqlDb.ExecContext(ctx, `delete from iam_role`)
	require.NoError(t, err)
	aliasRepoFn := func() (*talias.Repository, error) {
		return talias.NewRepository(t.Context(), rw, rw, kmsCache)
	}
	s, err := users.NewService(ctx, repoFn, aliasRepoFn, 1000)
	require.NoError(t, err)
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	proj2 := iam.TestProject(t, iamRepo, org1.GetPublicId(), iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))
	org2, proj3 := iam.TestScopes(t, iamRepo, iam.WithSkipAdminRoleCreation(true), iam.WithSkipDefaultRoleCreation(true))

	target1 := tcp.TestTarget(ctx, t, conn, proj1.GetPublicId(), "test address-1", target.WithAddress("8.8.8.8"))
	target2 := tcp.TestTarget(ctx, t, conn, proj2.GetPublicId(), "test address-2", target.WithAddress("8.8.8.8"))
	target3 := tcp.TestTarget(ctx, t, conn, proj3.GetPublicId(), "test address-3", target.WithAddress("8.8.8.8"))

	alias1 := talias.TestAlias(t, rw, "target1",
		talias.WithName("target1"),
		talias.WithDescription("target1"),
		talias.WithDestinationId(target1.GetPublicId()),
		talias.WithHostId(target1.GetPublicId()))
	alias2 := talias.TestAlias(t, rw, "target2",
		talias.WithName("target2"),
		talias.WithDescription("target2"),
		talias.WithDestinationId(target2.GetPublicId()),
		talias.WithHostId(target2.GetPublicId()))
	alias3 := talias.TestAlias(t, rw, "target3",
		talias.WithName("target3"),
		talias.WithDescription("target3"),
		talias.WithDestinationId(target3.GetPublicId()),
		talias.WithHostId(target3.GetPublicId()))

	fmt.Println(alias1, "\n", alias2, "\n", alias3)
	testcases := []struct {
		name string
		// setting returns user/account of a listing user which may be different than user in ListResolvableAliasesRequest
		setupInput              func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest)
		expectIdOutputFieldsMap map[string][]string
		wantErr                 error
	}{
		{
			name: "global role this and descendants grants return all aliases list same user",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=user;actions=list-resolvable-aliases;output_fields=id,created_time,name,value",
							"ids=*;type=target;actions=*",
						},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: listingUser.PublicId,
				}
			},
			expectIdOutputFieldsMap: map[string][]string{
				alias1.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
				alias2.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
				alias3.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
			},
		},
		{
			name: "global role this and org2 role children grants return all aliases list same user",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=user;actions=list-resolvable-aliases;output_fields=id,created_time,name,value",
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: org2.PublicId,
						Grants: []string{
							"ids=*;type=target;actions=*",
						},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: listingUser.PublicId,
				}
			},
			expectIdOutputFieldsMap: map[string][]string{
				alias3.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
			},
		},
		{
			name: "list other user without permissions returns nothing",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				testUser, _ := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{})()

				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=user;actions=list-resolvable-aliases;output_fields=id,created_time,name,value",
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: testUser.PublicId,
				}
			},
			expectIdOutputFieldsMap: map[string][]string{},
		},
		{
			name: "list other user with list-resolvable-aliases permissions but no targets permissions returns nothing",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				testUser, _ := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=user;actions=*",
						},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})()

				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=user;actions=list-resolvable-aliases;output_fields=id,created_time,name,value",
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: testUser.PublicId,
				}
			},
			expectIdOutputFieldsMap: map[string][]string{},
		},
		{
			name: "list other user with no list-resolvable-aliases permissions but all targets permissions returns nothing",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				testUser, _ := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=target;actions=*",
						},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})()

				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=user;actions=list-resolvable-aliases;output_fields=id,created_time,name,value",
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: testUser.PublicId,
				}
			},
			expectIdOutputFieldsMap: map[string][]string{
				alias1.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
				alias2.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
				alias3.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
			},
		},
		{
			name: "list other user with list-resolvable-aliases permissions and some targets permissions returns allowed targets",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				testUser, _ := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj3.PublicId,
						Grants: []string{
							fmt.Sprintf("ids=%s;type=target;actions=authorize-session", target3.GetPublicId()),
						},
						GrantScopes: []string{proj3.PublicId},
					},
					{
						RoleScopeId: proj2.PublicId,
						Grants: []string{
							fmt.Sprintf("ids=%s;type=target;actions=authorize-session", "*"),
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: org1.PublicId,
						Grants: []string{
							fmt.Sprintf("ids=%s;type=target;actions=authorize-session", target1.GetPublicId()),
						},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})()

				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							fmt.Sprintf("ids=%s;type=user;actions=list-resolvable-aliases;output_fields=id,created_time,name,value", testUser.PublicId),
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: testUser.PublicId,
				}
			},
			expectIdOutputFieldsMap: map[string][]string{
				alias1.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
				alias2.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
				alias3.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
			},
		},
		{
			name: "list other user with list-resolvable-aliases permissions and some targets permissions returns allowed with children grants granting different resources",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				testUser, _ := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"ids=*;type=target;actions=authorize-session"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"ids=*;type=target;actions=authorize-session"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=role;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})()

				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							fmt.Sprintf("ids=%s;type=user;actions=list-resolvable-aliases;output_fields=id,created_time,name,value", testUser.PublicId),
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: testUser.PublicId,
				}
			},
			expectIdOutputFieldsMap: map[string][]string{
				alias1.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
				alias2.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
			},
		},
		{
			name: "list other user with specific list-resolvable-aliases permissions and specific targets permissions returns allowed targets",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				testUser, _ := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=user;actions=list-resolvable-aliases;output_fields=created_time",
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							fmt.Sprintf("ids=%s,%s;type=target;actions=authorize-session", target2.GetPublicId(), target3.GetPublicId()),
						},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})()

				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							fmt.Sprintf("ids=%s;type=user;actions=list-resolvable-aliases;output_fields=id,created_time,name,value", testUser.PublicId),
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: testUser.PublicId,
				}
			},
			expectIdOutputFieldsMap: map[string][]string{
				alias2.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
				alias3.PublicId: {globals.IdField, globals.CreatedTimeField, globals.NameField, globals.ValueField},
			},
		},
		{
			name: "no permissions cannot list resolvable aliases",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							"ids=*;type=user;actions=list;output_fields=id,created_time,name,value",
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: listingUser.PublicId,
				}
			},
			wantErr: handlers.ForbiddenError(),
		},
		{
			name: "no permissions cannot list resolvable aliases from another user",
			setupInput: func(t *testing.T) (*iam.User, auth.Account, *pbs.ListResolvableAliasesRequest) {
				testUser, _ := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{})()

				listingUser, listingAccount := iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants: []string{
							fmt.Sprintf("ids=*;type=user;actions=delete"),
						},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})()
				return listingUser, listingAccount, &pbs.ListResolvableAliasesRequest{
					Id: testUser.PublicId,
				}
			},
			wantErr: handlers.ForbiddenError(),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account, input := tc.setupInput(t)
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.ListResolvableAliases(fullGrantAuthCtx, input)
			if tc.wantErr != nil {
				require.ErrorIs(t, tc.wantErr, tc.wantErr)
				return
			}
			require.NoError(t, err)
			var gotIds []string
			for _, i := range got.Items {
				gotIds = append(gotIds, i.Id)
			}
			require.ElementsMatch(t, gotIds, maps.Keys(tc.expectIdOutputFieldsMap))
			require.Len(t, got.Items, len(tc.expectIdOutputFieldsMap))

			for _, item := range got.Items {
				expectFields, ok := tc.expectIdOutputFieldsMap[item.GetId()]
				require.True(t, ok)
				handlers.TestAssertOutputFields(t, item, expectFields)
			}
		})
	}

}
