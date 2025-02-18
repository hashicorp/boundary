// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package aliases_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/aliases"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/aliases"
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
			userFunc func() (*iam.User, string)
			wantErr  error
			wantIDs  []string
		}{
			{
				name: "global role grant this with wildcard returns all created aliases",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*"},
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
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=alias;actions=*"},
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
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
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
				name: "global group role grant with wildcard returns all created aliases",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
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
				name: "global role grant this with a non-applicable type throws an error",
				input: &pbs.ListAliasesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: handlers.ApiErrorWithCode(codes.PermissionDenied),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
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
			userFunc        func() (*iam.User, string)
			inputWantErrMap map[*pbs.GetAliasRequest]error
		}{
			{
				name: "global role alias grant this scope with all permissions",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: nil,
					{Id: globalAlias2.PublicId}: nil,
				},
			},
			{
				name: "global role alias grant this scope with specific alias type",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: nil,
					{Id: globalAlias2.PublicId}: nil,
				},
			},
			{
				name: "global role alias grant this scope with non-applicable type",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=group;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputWantErrMap: map[*pbs.GetAliasRequest]error{
					{Id: globalAlias1.PublicId}: handlers.ForbiddenError(),
					{Id: globalAlias2.PublicId}: handlers.ForbiddenError(),
				},
			},
			{
				name: "global role alias grant this scope with descendants scope",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
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
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for input, wantErr := range tc.inputWantErrMap {
					_, err := s.GetAlias(fullGrantAuthCtx, input)
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
			userFunc          func() (*iam.User, string)
			canCreateInScopes map[*pbs.CreateAliasRequest]error
		}{
			{
				name: "direct grant all can create all",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.one"}}: nil,
				},
			},
			{
				name: "direct grant with alias type can create",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.two"}}: nil,
				},
			},
			{
				name: "groups grant all can create all",
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.three"}}: nil,
				},
			},
			{
				name: "ldap grant all can create all",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canCreateInScopes: map[*pbs.CreateAliasRequest]error{
					{Item: &pb.Alias{ScopeId: globals.GlobalPrefix, Type: "target", Value: "valid.alias.four"}}: nil,
				},
			},
			{
				name: "oidc grant all can create all",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*"},
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
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

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
			setupScopesResourcesAndUser func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, string))
			wantErr                     error
		}{
			{
				name: "global_scope_group_good_grant_success",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, string)) {
					globalAlias := target.TestAlias(t, rw, "test.alias.one", target.WithDescription("alias_1"), target.WithName("alias_one"))
					return globalAlias, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: globals.GlobalPrefix,
							Grants:      []string{"id=*;type=*;actions=*"},
							GrantScopes: []string{globals.GrantScopeThis},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "grant specific scope success",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, string)) {
					globalAlias := target.TestAlias(t, rw, "test.alias.two", target.WithDescription("alias_2"), target.WithName("alias_two"))
					return globalAlias, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							Grants:      []string{"ids=*;type=*;actions=*"},
							GrantScopes: []string{globals.GlobalPrefix},
						},
					})
				},
				wantErr: nil,
			},
			{
				name: "grant specific resource and scope success",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, string)) {
					globalAlias := target.TestAlias(t, rw, "test.alias.three", target.WithDescription("alias_3"), target.WithName("alias_three"))
					return globalAlias, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
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
				name: "no grant fails update",
				setupScopesResourcesAndUser: func(t *testing.T, conn *db.DB, rw *db.Db, iamRepo *iam.Repository, kmsCache *kms.Kms) (*target.Alias, func() (*iam.User, string)) {
					globalAlias := target.TestAlias(t, rw, "test.alias.four", target.WithDescription("alias_4"), target.WithName("alias_four"))
					return globalAlias, iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeId: globals.GlobalPrefix,
							Grants:      []string{"id=*;type=*;actions=*"},
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
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
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
			userFunc          func() (*iam.User, string)
			canDeleteInScopes map[*pbs.DeleteAliasRequest]error
		}{
			{
				name: "grant all can delete all",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canDeleteInScopes: map[*pbs.DeleteAliasRequest]error{
					{Id: globalAlias1.PublicId}: nil,
				},
			},
			{
				name: "grant alias type can delete aliases",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=alias;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				canDeleteInScopes: map[*pbs.DeleteAliasRequest]error{
					{Id: globalAlias2.PublicId}: nil,
				},
			},
			{
				name: "grant non-applicable type cannot delete aliases",
				userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=group;actions=*"},
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
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
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
