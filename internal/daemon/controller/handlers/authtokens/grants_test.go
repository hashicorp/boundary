// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtokens_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	a "github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	at "github.com/hashicorp/boundary/internal/daemon/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	kmsCache := kms.TestKms(t, conn, wrap)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	atRepoFn := func() (*authtoken.Repository, error) { return atRepo, nil }

	s, err := at.NewService(ctx, atRepoFn, iamRepoFn, 1000)

	require.NoError(t, err)

	org1, _ := iam.TestScopes(t, iamRepo)
	org2, _ := iam.TestScopes(t, iamRepo)

	globalAT := authtoken.TestAuthToken(t, conn, kmsCache, globals.GlobalPrefix)
	org1AT := authtoken.TestAuthToken(t, conn, kmsCache, org1.GetPublicId())
	org2AT := authtoken.TestAuthToken(t, conn, kmsCache, org2.GetPublicId())

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name            string
			input           *pbs.ListAuthTokensRequest
			userFunc        func() (*iam.User, a.Account)
			wantErr         error
			wantIDs         []string
			expectOutfields []string
		}{
			{
				name: "global role grant this returns global token",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,scope,user_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalAT.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.ScopeField,
					globals.UserIdField,
				},
			},
			{
				name: "global role grant this and children returns global and org tokens",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-token;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalAT.PublicId, org1AT.PublicId, org2AT.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.ScopeField,
					globals.UserIdField,
					globals.AuthMethodIdField,
					globals.AccountIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.ApproximateLastUsedTimeField,
					globals.ExpirationTimeField,
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "global role grant this and descendants returns global and org tokens",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,approximate_last_used_time,expiration_time,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIDs: []string{globalAT.PublicId, org1AT.PublicId, org2AT.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ApproximateLastUsedTimeField,
					globals.ExpirationTimeField,
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "global role grant descendants with recursive returns global and org tokens",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,approximate_last_used_time,expiration_time,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: nil,
				wantIDs: []string{org1AT.PublicId, org2AT.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ApproximateLastUsedTimeField,
					globals.ExpirationTimeField,
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "global role grant descendants without recursive returns error",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: false,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,approximate_last_used_time,expiration_time,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: handlers.ForbiddenError(),
				wantIDs: nil,
			},
			{
				name: "org role grant this returns org tokens",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   org1.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,auth_method_id,account_id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{org1AT.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.AuthMethodIdField,
					globals.AccountIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
				},
			},
			{
				name: "org role grant this and children returns org tokens",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   org1.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{org1AT.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.ScopeField,
					globals.UserIdField,
					globals.AuthMethodIdField,
					globals.AccountIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.ApproximateLastUsedTimeField,
					globals.ExpirationTimeField,
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "global role grant this and children returns org tokens",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   org1.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				wantIDs: []string{org1AT.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.ScopeField,
					globals.UserIdField,
					globals.AuthMethodIdField,
					globals.AccountIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.ApproximateLastUsedTimeField,
					globals.ExpirationTimeField,
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "org role grant this pinned id returns org tokens",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   org1.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{fmt.Sprintf("ids=%s;type=auth-token;actions=*", org1AT.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				wantIDs: []string{org1AT.PublicId},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.ScopeField,
					globals.UserIdField,
					globals.AuthMethodIdField,
					globals.AccountIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.ApproximateLastUsedTimeField,
					globals.ExpirationTimeField,
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "org role grant this does not list other org tokens",
				input: &pbs.ListAuthTokensRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr:         nil,
				wantIDs:         nil,
				expectOutfields: nil,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListAuthTokens(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				var gotIDs []string
				for _, g := range got.Items {
					fmt.Println("ID:", g.GetId(), "Scope:", g.GetScopeId())
					gotIDs = append(gotIDs, g.GetId())
				}

				for _, id := range tc.wantIDs {
					require.Contains(t, gotIDs, id)
				}
				for _, item := range got.Items {
					handlers.TestAssertOutputFields(t, item, tc.expectOutfields)
				}
			})
		}
	})

	t.Run("Get", func(t *testing.T) {
		testcases := []struct {
			name            string
			input           *pbs.GetAuthTokenRequest
			userFunc        func() (*iam.User, a.Account)
			wantErr         error
			wantId          string
			expectOutfields []string
		}{
			{
				name: "global role grant this returns global token",
				input: &pbs.GetAuthTokenRequest{
					Id: globalAT.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=read;output_fields=id,scope_id,scope,user_id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.ScopeField,
					globals.UserIdField,
				},
				wantId: globalAT.PublicId,
			},
			{
				name: "org role grant this returns org token",
				input: &pbs.GetAuthTokenRequest{
					Id: org1AT.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=auth-token;actions=read;output_fields=id,auth_method_id,account_id,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				expectOutfields: []string{
					globals.IdField,
					globals.AuthMethodIdField,
					globals.AccountIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
				},
				wantId: org1AT.PublicId,
			},
			{
				name: "org role grant this cannot read global token",
				input: &pbs.GetAuthTokenRequest{
					Id: globalAT.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr:         handlers.ForbiddenError(),
				expectOutfields: nil,
			},
			{
				name: "global role grant this and children can read org token",
				input: &pbs.GetAuthTokenRequest{
					Id: org1AT.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id,scope,user_id"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				wantErr: nil,
				expectOutfields: []string{
					globals.IdField,
					globals.AuthMethodIdField,
					globals.ScopeIdField,
					globals.ScopeField,
					globals.UserIdField,
					globals.AccountIdField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.ApproximateLastUsedTimeField,
					globals.ExpirationTimeField,
					globals.AuthorizedActionsField,
				},
				wantId: org1AT.PublicId,
			},
			{
				name: "org role grant this pinned id returns org token",
				input: &pbs.GetAuthTokenRequest{
					Id: org1AT.PublicId,
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{fmt.Sprintf("ids=%s;type=auth-token;actions=read;output_fields=id,scope_id,scope,user_id", org1AT.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				wantErr: nil,
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeIdField,
					globals.ScopeField,
					globals.UserIdField,
				},
				wantId: org1AT.PublicId,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, acct := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.GetAuthToken(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
				assert.Equal(t, tc.wantId, got.GetItem().Id)
				handlers.TestAssertOutputFields(t, got.GetItem(), tc.expectOutfields)
			})
		}
	})
}

func TestGrants_CreateActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	kmsCache := kms.TestKms(t, conn, wrap)

	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	atRepoFn := func() (*authtoken.Repository, error) { return atRepo, nil }

	s, err := at.NewService(ctx, atRepoFn, iamRepoFn, 1000)
	require.NoError(t, err)

	org1, _ := iam.TestScopes(t, iamRepo)
	org2, _ := iam.TestScopes(t, iamRepo)
	org3, _ := iam.TestScopes(t, iamRepo)
	pinnedId := authtoken.TestAuthToken(t, conn, kmsCache, org2.GetPublicId())
	selfToken := authtoken.TestAuthToken(t, conn, kmsCache, org3.GetPublicId())

	t.Run("Delete", func(t *testing.T) {
		testcases := []struct {
			name          string
			createTokenFn func() *authtoken.AuthToken
			userFunc      func() (*iam.User, a.Account)
			ctxAuthToken  func(ctx context.Context, user *iam.User, acctId string) (*authtoken.AuthToken, error)
			wantErr       error
		}{
			{
				name: "global role grant this deletes global token",
				createTokenFn: func() *authtoken.AuthToken {
					return authtoken.TestAuthToken(t, conn, kmsCache, globals.GlobalPrefix)
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				ctxAuthToken: func(ctx context.Context, user *iam.User, acctId string) (*authtoken.AuthToken, error) {
					return atRepo.CreateAuthToken(ctx, user, acctId)
				},
				wantErr: nil,
			},
			{
				name: "global role grant this and children can delete org tokens",
				createTokenFn: func() *authtoken.AuthToken {
					return authtoken.TestAuthToken(t, conn, kmsCache, org1.GetPublicId())
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-token;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				ctxAuthToken: func(ctx context.Context, user *iam.User, acctId string) (*authtoken.AuthToken, error) {
					return atRepo.CreateAuthToken(ctx, user, acctId)
				},
				wantErr: nil,
			},
			{
				name: "global role grant this and descendants can delete org tokens",
				createTokenFn: func() *authtoken.AuthToken {
					return authtoken.TestAuthToken(t, conn, kmsCache, org2.GetPublicId())
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				ctxAuthToken: func(ctx context.Context, user *iam.User, acctId string) (*authtoken.AuthToken, error) {
					return atRepo.CreateAuthToken(ctx, user, acctId)
				},
				wantErr: nil,
			},
			{
				name: "global role grant this can delete pinned org token",
				createTokenFn: func() *authtoken.AuthToken {
					return pinnedId
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=auth-token;actions=*", pinnedId.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				ctxAuthToken: func(ctx context.Context, user *iam.User, acctId string) (*authtoken.AuthToken, error) {
					return atRepo.CreateAuthToken(ctx, user, acctId)
				},
				wantErr: nil,
			},
			{
				name: "org role grant this can delete self",
				createTokenFn: func() *authtoken.AuthToken {
					return selfToken
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=delete:self"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				ctxAuthToken: func(ctx context.Context, user *iam.User, acctId string) (*authtoken.AuthToken, error) {
					return selfToken, nil
				},
				wantErr: nil,
			},
			{
				name: "org role grant this can't delete global",
				createTokenFn: func() *authtoken.AuthToken {
					return authtoken.TestAuthToken(t, conn, kmsCache, globals.GlobalPrefix)
				},
				userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{org2.PublicId},
					},
				}),
				ctxAuthToken: func(ctx context.Context, user *iam.User, acctId string) (*authtoken.AuthToken, error) {
					return atRepo.CreateAuthToken(ctx, user, acctId)
				},
				wantErr: handlers.ForbiddenError(),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, acct := tc.userFunc()
				inputToken := tc.createTokenFn()
				input := &pbs.DeleteAuthTokenRequest{
					Id: inputToken.PublicId,
				}
				authToken, err := tc.ctxAuthToken(ctx, user, acct.GetPublicId())
				require.NoError(t, err)
				// authToken, err := atRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, authToken, iamRepo)
				_, finalErr := s.DeleteAuthToken(fullGrantAuthCtx, input)
				if tc.wantErr != nil {
					require.ErrorIs(t, finalErr, tc.wantErr)
					return
				}
				require.NoError(t, finalErr)
			})
		}
	})
}
