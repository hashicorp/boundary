// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package aliases_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	cauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/aliases"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target/tcp"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/aliases"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
//		Scopes [resource]:
//			- globalAlias1 [globalAlias]
//			- globalAlias2 [globalAlias]
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*target.Repository, error) {
		return target.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
	require.NoError(t, err)
	globalAlias1 := target.TestAlias(t, rw, "test.alias.one", target.WithDescription("alias_1"), target.WithName("alias_one"))
	globalAlias2 := target.TestAlias(t, rw, "test.alias.two", target.WithDescription("alias_2"), target.WithName("alias_two"))
	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name     string
			input    *pbs.ListAliasesRequest
			userFunc func() (*iam.User, auth.Account)
			wantErr  error
			wantIDs  []string
		}{
			{
				name: "global role grant this with wildcard returns all created aliases",
				input: &pbs.ListAliasesRequest{
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
				wantErr: nil,
				wantIDs: []string{globalAlias1.PublicId, globalAlias2.PublicId},
			},
			{
				name: "global role grant this with type set to 'alias' returns all created aliases",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalAlias1.PublicId, globalAlias2.PublicId},
			},
			{
				name: "global LDAP role grant with wildcard returns all created aliases",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalAlias1.PublicId, globalAlias2.PublicId},
			},
			{
				name: "global alias role grant with wildcard returns all created aliases",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalAlias1.PublicId, globalAlias2.PublicId},
			},
			{
				name: "global alias role grant with list action returns an empty list",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=list"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{},
			},
			{
				name: "global alias role grant with list action returns all created aliases",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=no-op,list"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalAlias1.PublicId, globalAlias2.PublicId},
			},
			{
				name: "global role grant with a non-applicable type returns a permission denied error",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListAliases(fullGrantAuthCtx, tc.input)
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
			userFunc        func() (*iam.User, auth.Account)
			inputWantErrMap map[*pbs.GetAliasRequest]error
		}{
			{
				name: "global role alias grant with this scope with all permissions returns all aliases",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: nil,
					{Id: globalAlias2.PublicId}: nil,
				},
			},
			{
				name: "global role alias grant this scope with specific alias type returns all aliases",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: nil,
					{Id: globalAlias2.PublicId}: nil,
				},
			},
			{
				name: "global role alias grant this scope with specific alias type and id returns all aliases",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=alias;actions=*", globalAlias1.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: nil,
				},
			},
			{
				name: "global role alias grant this scope with specific alias type and read action returns all aliases",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: nil,
					{Id: globalAlias2.PublicId}: nil,
				},
			},
			{
				name: "global role alias grant this scope with non-applicable type returns a permission denied error",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: handlers.ForbiddenError(),
					{Id: globalAlias2.PublicId}: handlers.ForbiddenError(),
				},
			},
			{
				name: "global role alias grant this scope with descendants scope returns a permission denied error",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: handlers.ForbiddenError(),
					{Id: globalAlias2.PublicId}: handlers.ForbiddenError(),
				},
			},
			{
				name: "global role alias grant this scope with list action returns a permission denied error",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=list"},
						GrantScopes: []string{globals.GlobalPrefix},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: handlers.ForbiddenError(),
					{Id: globalAlias2.PublicId}: handlers.ForbiddenError(),
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for input, wantErr := range tc.inputWantErrMap {
					_, err := s.GetAlias(fullGrantAuthCtx, input)
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
				}
			})
		}
	})

	t.Run("authorized action", func(t *testing.T) {
		testcases := []struct {
			name                  string
			input                 *pbs.ListAliasesRequest
			userFunc              func() (*iam.User, auth.Account)
			wantErr               error
			wantAuthorizedActions []string
		}{
			{
				name: "global role grant this with wildcard returns all created aliases",
				input: &pbs.ListAliasesRequest{
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
				wantErr:               nil,
				wantAuthorizedActions: []string{"read", "update", "delete", "no-op"},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListAliases(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				for _, item := range got.Items {
					require.ElementsMatch(t, tc.wantAuthorizedActions, item.AuthorizedActions)
				}
			})
		}
	})
}

// TestGrants_WriteActions tests write actions to assert that grants are being applied properly
//
//	[create, update, delete]
//	 Role - which scope the role is created in
//			- global level
//		Scopes [resource]:
//			- globalAlias1 [globalAlias]
//			- globalAlias2 [globalAlias]
func TestGrants_WriteActions(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		iamRepoFn := func() (*iam.Repository, error) {
			return iamRepo, nil
		}
		repoFn := func() (*target.Repository, error) {
			return target.NewRepository(ctx, rw, rw, kmsCache)
		}
		s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
		require.NoError(t, err)

		testcases := []struct {
			name              string
			userFunc          func() (*iam.User, auth.Account)
			canCreateInScopes map[*pbs.CreateAliasRequest]error
		}{
			{
				name: "direct grant all can create all",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.one"}}: nil,
				},
			},
			{
				name: "direct grant with alias type can create",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.two"}}: nil,
				},
			},
			{
				name: "groups grant all can create all",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.three"}}: nil,
				},
			},
			{
				name: "ldap grant all can create all",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.four"}}: nil,
				},
			},
			{
				name: "oidc grant all can create all",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.five"}}: nil,
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				for req, wantErr := range tc.canCreateInScopes {
					_, err := s.CreateAlias(fullGrantAuthCtx, req)
					if wantErr != nil {
						require.ErrorIs(t, err, wantErr)
						continue
					}
					require.NoError(t, err)
				}
			})
		}
	})

	t.Run("update", func(t *testing.T) {
		testcases := []struct {
			name                        string
			setupScopesResourcesAndUser func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, auth.Account))
			wantErr                     error
		}{
			{
				name: "grant with wildcard can update alias",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, auth.Account)) {
					globalAlias := target.TestAlias(t, rw, "test.alias.one", target.WithDescription("alias_1"), target.WithName("alias_one"))
					return globalAlias, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
				name: "grant with specific scope can update alias",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, auth.Account)) {
					globalAlias := target.TestAlias(t, rw, "test.alias.two", target.WithDescription("alias_2"), target.WithName("alias_two"))
					return globalAlias, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: globals.GlobalPrefix,
							Grants:      []string{"ids=*;type=*;actions=*"},
							GrantScopes: []string{globals.GlobalPrefix},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "grant specific resource and scope success",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, auth.Account)) {
					globalAlias := target.TestAlias(t, rw, "test.alias.three", target.WithDescription("alias_3"), target.WithName("alias_three"))
					return globalAlias, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: globals.GlobalPrefix,
							Grants:      []string{fmt.Sprintf("ids=%s;types=alias;actions=*", globalAlias.PublicId)},
							GrantScopes: []string{globals.GlobalPrefix},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "grants with children scope only fails update",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, auth.Account)) {
					globalAlias := target.TestAlias(t, rw, "test.alias.four", target.WithDescription("alias_4"), target.WithName("alias_four"))
					return globalAlias, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
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
				kmsCache := kms.TestKms(t, conn, wrap)
				iamRepo := iam.TestRepo(t, conn, wrap)
				atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
				require.NoError(t, err)
				iamRepoFn := func() (*iam.Repository, error) {
					return iamRepo, nil
				}
				repoFn := func() (*target.Repository, error) {
					return target.NewRepository(ctx, rw, rw, kmsCache)
				}

				s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
				require.NoError(t, err)
				original, userFunc := tc.setupScopesResourcesAndUser(t, conn, rw, iamRepo, kmsCache)
				user, accountID := userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.UpdateAlias(fullGrantAuthCtx, &pbs.UpdateAliasRequest{
					Id: original.PublicId,
					Item: &pb.Alias{
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

	t.Run("delete", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		iamRepoFn := func() (*iam.Repository, error) {
			return iamRepo, nil
		}
		repoFn := func() (*target.Repository, error) {
			return target.NewRepository(ctx, rw, rw, kmsCache)
		}
		s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
		require.NoError(t, err)
		globalAlias1 := target.TestAlias(t, rw, "test.alias.one", target.WithDescription("alias_1"), target.WithName("alias_one"))
		globalAlias2 := target.TestAlias(t, rw, "test.alias.two", target.WithDescription("alias_2"), target.WithName("alias_two"))
		globalAlias3 := target.TestAlias(t, rw, "test.alias.three", target.WithDescription("alias_3"), target.WithName("alias_three"))

		testcases := []struct {
			name              string
			userFunc          func() (*iam.User, auth.Account)
			canDeleteInScopes map[*pbs.DeleteAliasRequest]error
		}{
			{
				name: "grant all can delete all",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canDeleteInScopes: map[*pbs.DeleteAliasRequest]error{
					{Id: globalAlias1.PublicId}: nil,
				},
			},
			{
				name: "grant alias type can delete aliases",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canDeleteInScopes: map[*pbs.DeleteAliasRequest]error{
					{Id: globalAlias2.PublicId}: nil,
				},
			},
			{
				name: "grant non-applicable type cannot delete aliases",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canDeleteInScopes: map[*pbs.DeleteAliasRequest]error{
					{Id: globalAlias3.PublicId}: handlers.ForbiddenError(),
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for req, wantErr := range tc.canDeleteInScopes {
					_, err := s.DeleteAlias(fullGrantAuthCtx, req)
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

func TestOutputFields(t *testing.T) {
	genUuid := func(t *testing.T) string {
		id, err := uuid.GenerateUUID()
		require.NoError(t, err)
		return id
	}
	t.Run("ListAlias", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		iamRepoFn := func() (*iam.Repository, error) {
			return iamRepo, nil
		}
		repoFn := func() (*target.Repository, error) {
			return target.NewRepository(ctx, rw, rw, kmsCache)
		}
		s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
		require.NoError(t, err)

		_, p := iam.TestScopes(t, iamRepo)
		tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget")

		globalAlias1 := target.TestAlias(
			t,
			rw,
			"test.alias.one",
			target.WithDescription("alias_1"),
			target.WithName("alias_one"),
			target.WithDestinationId(tar.GetPublicId()),
			target.WithHostId("hst_1234567890"),
		)

		testcases := []struct {
			name     string
			userFunc func() (*iam.User, auth.Account)
			// keys are the alias IDs | this also means 'id' is required in the outputfields for assertions to work properly
			expectOutfields map[string][]string
		}{
			{
				name: "grant with output_fields only returns: name, version, description",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=id,name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: map[string][]string{
					globalAlias1.PublicId: {globals.IdField, globals.NameField, globals.DescriptionField},
				},
			},
			{
				name: "grant with output_fields only returns: scope_id, destination_id, type, value",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=id,scope_id,destination_id,type,value"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: map[string][]string{
					globalAlias1.PublicId: {globals.IdField, globals.ScopeIdField, globals.DestinationIdField, globals.TypeField, globals.ValueField},
				},
			},
			{
				name: "grant with output_fields only returns: update_time, create_time",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=id,updated_time,created_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: map[string][]string{
					globalAlias1.PublicId: {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "multiple grants with different output_fields returns all fields",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=id,name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=id,scope_id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=id,scope_id,destination_id,type,value,host_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: map[string][]string{
					globalAlias1.PublicId: {
						globals.IdField,
						globals.NameField,
						globals.DescriptionField,
						globals.ScopeIdField,
						globals.CreatedTimeField,
						globals.UpdatedTimeField,
						globals.DestinationIdField,
						globals.TypeField,
						globals.ValueField,
						globals.HostIdField,
					},
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				out, err := s.ListAliases(fullGrantAuthCtx, &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				})
				require.NoError(t, err)
				for _, item := range out.Items {
					handlers.TestAssertOutputFields(t, item, tc.expectOutfields[item.Id])
				}
			})
		}
	})

	t.Run("GetAlias", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		iamRepoFn := func() (*iam.Repository, error) {
			return iamRepo, nil
		}
		repoFn := func() (*target.Repository, error) {
			return target.NewRepository(ctx, rw, rw, kmsCache)
		}
		s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
		require.NoError(t, err)

		_, p := iam.TestScopes(t, iamRepo)
		tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget")

		globalAlias1 := target.TestAlias(
			t,
			rw,
			"test.alias.one",
			target.WithDescription("alias_1"),
			target.WithName("alias_one"),
			target.WithDestinationId(tar.GetPublicId()),
			target.WithHostId("hst_1234567890"),
		)

		testcases := []struct {
			name            string
			userFunc        func() (*iam.User, auth.Account)
			expectOutfields []string
		}{
			{
				name: "grant with output_fields only returns: name and description",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read;output_fields=name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.NameField, globals.DescriptionField},
			},
			{
				name: "grant with output_fields only returns: scopeId and value",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read;output_fields=scope_id,value"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.ScopeIdField, globals.ValueField},
			},
			{
				name: "grant with output_fields only returns: updated_time and create_time",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read;output_fields=updated_time,created_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
			},
			{
				name: "grant with output_fields only returns: id, destination_id, host_id, version",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read;output_fields=id,destination_id,host_id,version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.IdField, globals.DestinationIdField, globals.HostIdField, globals.VersionField},
			},
			{
				name: "composite grants id, authorized_actions, member_ids",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read;output_fields=destination_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read;output_fields=type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=read;output_fields=value"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.IdField, globals.DestinationIdField, globals.TypeField, globals.ValueField},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				out, err := s.GetAlias(fullGrantAuthCtx, &pbs.GetAliasRequest{Id: globalAlias1.PublicId})
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
			})
		}
	})

	t.Run("CreateAlias", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		iamRepoFn := func() (*iam.Repository, error) {
			return iamRepo, nil
		}
		repoFn := func() (*target.Repository, error) {
			return target.NewRepository(ctx, rw, rw, kmsCache)
		}
		s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
		require.NoError(t, err)

		_, p := iam.TestScopes(t, iamRepo)
		tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget")

		testcases := []struct {
			name            string
			userFunc        func() (*iam.User, auth.Account)
			input           *pbs.CreateAliasRequest
			expectOutfields []string
		}{
			{
				name: "grant with output_fields only returns: name and description",
				input: &pbs.CreateAliasRequest{
					Item: &pb.Alias{
						Name:        &wrapperspb.StringValue{Value: genUuid(t)},
						Description: &wrapperspb.StringValue{Value: genUuid(t)},
						ScopeId:     globals.GlobalPrefix,
						Type:        "target",
						Value:       "valid.alias.one",
					},
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.NameField, globals.DescriptionField},
			},
			{
				name: "grant with output_fields only returns: scope_id and value",
				input: &pbs.CreateAliasRequest{
					Item: &pb.Alias{
						Name:        &wrapperspb.StringValue{Value: genUuid(t)},
						Description: &wrapperspb.StringValue{Value: genUuid(t)},
						ScopeId:     globals.GlobalPrefix,
						Type:        "target",
						Value:       "valid.alias.two",
					},
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=scope_id,value"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.ScopeIdField, globals.ValueField},
			},
			{
				name: "grant with output_fields only returns: update_time and create_time",
				input: &pbs.CreateAliasRequest{
					Item: &pb.Alias{
						Name:        &wrapperspb.StringValue{Value: genUuid(t)},
						Description: &wrapperspb.StringValue{Value: genUuid(t)},
						ScopeId:     globals.GlobalPrefix,
						Type:        "target",
						Value:       "valid.alias.three",
					},
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=updated_time,created_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
			},
			{
				name: "grant with output_fields only returns: id, destination_id, value, version",
				input: &pbs.CreateAliasRequest{
					Item: &pb.Alias{
						Name:          &wrapperspb.StringValue{Value: genUuid(t)},
						Description:   &wrapperspb.StringValue{Value: genUuid(t)},
						ScopeId:       globals.GlobalPrefix,
						Type:          "target",
						Value:         "valid.alias.four",
						DestinationId: &wrapperspb.StringValue{Value: tar.GetPublicId()},
					},
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=id,destination_id,value,version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.IdField, globals.DestinationIdField, globals.ValueField, globals.VersionField},
			},
			{
				name: "composite grants all fields",
				input: &pbs.CreateAliasRequest{
					Item: &pb.Alias{
						Name:          &wrapperspb.StringValue{Value: genUuid(t)},
						Description:   &wrapperspb.StringValue{Value: genUuid(t)},
						ScopeId:       globals.GlobalPrefix,
						Type:          "target",
						Value:         "valid.alias.five",
						DestinationId: &wrapperspb.StringValue{Value: tar.GetPublicId()},
					},
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=destination_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=scope_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=name"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=created_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=value"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=host_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=*;output_fields=version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.DestinationIdField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.ValueField,
					globals.TypeField,
					globals.HostIdField,
					globals.VersionField,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				out, err := s.CreateAlias(fullGrantAuthCtx, tc.input)
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
			})
		}
	})

	t.Run("UpdateAlias", func(t *testing.T) {
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		iamRepoFn := func() (*iam.Repository, error) {
			return iamRepo, nil
		}
		repoFn := func() (*target.Repository, error) {
			return target.NewRepository(ctx, rw, rw, kmsCache)
		}
		_, p := iam.TestScopes(t, iamRepo)
		tar := tcp.TestTarget(ctx, t, conn, p.GetPublicId(), "testTarget")

		// this can be used across test cases because we're only testing for output fields, not the update behaviors
		inputFunc := func(t *testing.T) *pbs.UpdateAliasRequest {
			alias1 := "test.alias." + genUuid(t)
			globalAlias1 := target.TestAlias(
				t,
				rw,
				alias1,
				target.WithDescription("alias_1"),
				target.WithName("alias_one"),
				target.WithDestinationId(tar.GetPublicId()),
				target.WithHostId("hst_1234567890"),
			)
			return &pbs.UpdateAliasRequest{
				Id: globalAlias1.PublicId,
				Item: &pb.Alias{
					Name:        &wrapperspb.StringValue{Value: genUuid(t)},
					Description: &wrapperspb.StringValue{Value: genUuid(t)},
					Version:     globalAlias1.Version,
				},
				UpdateMask: &fieldmaskpb.FieldMask{
					Paths: []string{"name", "description"},
				},
			}
		}

		s, err := aliases.NewService(ctx, repoFn, iamRepoFn, 1000)
		require.NoError(t, err)
		testcases := []struct {
			name            string
			userFunc        func() (*iam.User, auth.Account)
			expectOutfields []string
		}{
			{
				name: "grant with output_fields only returns: name and description",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=name,description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.NameField, globals.DescriptionField},
			},
			{
				name: "grant with output_fields only returns: scope_id and value",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=scope_id,value"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.ScopeIdField, globals.ValueField},
			},
			{
				name: "grant with output_fields only returns: update_time and create_time",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=updated_time,created_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.UpdatedTimeField, globals.CreatedTimeField},
			},
			{
				name: "grant with output_fields only returns: id, destination_id, value, version",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=id,destination_id,value,version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{globals.IdField, globals.DestinationIdField, globals.ValueField, globals.VersionField},
			},
			{
				name: "composite grants all fields",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=scope_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=name"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=description"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=created_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=destination_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=type"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=value"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=alias;actions=update;output_fields=host_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.DestinationIdField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.ValueField,
					globals.TypeField,
					globals.HostIdField,
					globals.VersionField,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				out, err := s.UpdateAlias(fullGrantAuthCtx, inputFunc(t))
				require.NoError(t, err)
				handlers.TestAssertOutputFields(t, out.Item, tc.expectOutfields)
			})
		}
	})
}
