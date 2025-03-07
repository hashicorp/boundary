// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtokens_test

import (
	"context"
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
	at "github.com/hashicorp/boundary/internal/daemon/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

// TestGrants_List tests list actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
//			- org level
//		Grant - what IAM grant scope is set for the permission
//			- global: descendant
//			- org: children
//		Scopes [resource]:
//			- global [globalAT]
//				- org1 [org1AT]
//				- org2 [org2AT]
func TestGrants_List(t *testing.T) {
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

	testcases := []struct {
		name            string
		input           *pbs.ListAuthTokensRequest
		userFunc        func() (user *iam.User, account auth.Account)
		wantErr         error
		wantIDs         []string
		expectOutfields map[string][]string
	}{
		{
			name: "direct user - global grant with auth-token type with list,read actions returns all auth-tokens",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,scope_id,type,token,user_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantIDs: []string{globalAT.PublicId, org1AT.PublicId, org2AT.PublicId},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
				org1AT.PublicId:   {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
				org2AT.PublicId:   {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
			},
		},
		{
			name: "group user - global grant with auth-token type with list,read actions returns all auth-tokens",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,authorized_actions,account_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantIDs: []string{globalAT.PublicId, org1AT.PublicId, org2AT.PublicId},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.AuthorizedActionsField, globals.AccountIdField},
				org1AT.PublicId:   {globals.IdField, globals.AuthorizedActionsField, globals.AccountIdField},
				org2AT.PublicId:   {globals.IdField, globals.AuthorizedActionsField, globals.AccountIdField},
			},
		},
		{
			name: "ldap user - global grant with auth-token type with list,read actions returns all auth-tokens",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,approximate_last_used_time"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantIDs: []string{globalAT.PublicId, org1AT.PublicId, org2AT.PublicId},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.ApproximateLastUsedTimeField},
				org1AT.PublicId:   {globals.IdField, globals.ApproximateLastUsedTimeField},
				org2AT.PublicId:   {globals.IdField, globals.ApproximateLastUsedTimeField},
			},
		},
		{
			name: "oidc user - global grant with auth-token type with list,read actions returns all auth-tokens",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantIDs: []string{globalAT.PublicId, org1AT.PublicId, org2AT.PublicId},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField},
				org1AT.PublicId:   {globals.IdField},
				org2AT.PublicId:   {globals.IdField},
			},
		},
		{
			name: "org grant with this grant scope, auth-token type with list,read actions returns all auth-tokens",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   org1.PublicId,
				Recursive: true,
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,scope_id,type,token,user_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantIDs: []string{org1AT.PublicId},
			expectOutfields: map[string][]string{
				org1AT.PublicId: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
			},
		},
		{
			name: "global grant with this grant scope, auth-token type with list,read actions returns all auth-tokens",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=list,read;output_fields=id,created_time,updated_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantIDs: []string{globalAT.PublicId},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
		},
		{
			name: "global grant with this grant scope, auth-token type with list,no-op actions returns all auth-tokens",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=list,no-op;output_fields=id,scope_id,type,token,user_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantIDs: []string{globalAT.PublicId},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
			},
		},
		{
			name: "global grant with this+children grant scope, with wildcard returns all auth-tokens",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			wantIDs: []string{globalAT.PublicId, org1AT.PublicId, org2AT.PublicId},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.ScopeIdField},
				org1AT.PublicId:   {globals.IdField, globals.ScopeIdField},
				org2AT.PublicId:   {globals.IdField, globals.ScopeIdField},
			},
		},
		{
			name: "global grant with children grant scope, auth-token type with list,no-op actions returns empty list",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=list"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: nil,
			wantIDs: []string{},
		},
		{
			name: "global grant with non-applicable grant returns empty list",
			input: &pbs.ListAuthTokensRequest{
				ScopeId:   globals.GlobalPrefix,
				Recursive: true,
			},
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=list"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: nil,
			wantIDs: []string{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			t.Cleanup(func() {
				// cleanup toke created token for auth
				atRepo.DeleteAuthToken(ctx, tok.GetPublicId())
			})
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, finalErr := s.ListAuthTokens(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, finalErr, tc.wantErr)
				return
			}
			require.NoError(t, finalErr)
			var gotIDs []string
			for _, g := range got.Items {
				gotIDs = append(gotIDs, g.GetId())
			}
			for _, id := range tc.wantIDs {
				require.Contains(t, gotIDs, id)
			}
			for _, item := range got.Items {
				// we want to skip the token we created
				if item.GetId() != tok.GetPublicId() {
					handlers.TestAssertOutputFields(t, item, tc.expectOutfields[item.GetId()])
				}
			}
		})
	}
}

func TestGrants_Read(t *testing.T) {
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

	testcases := []struct {
		name            string
		userFunc        func() (user *iam.User, account auth.Account)
		inputWantErrMap map[*pbs.GetAuthTokenRequest]error
		expectOutfields map[string][]string
	}{
		{
			name: "direct user - global grant with auth-token type with read action can read all auth-tokens",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read;output_fields=id,scope_id,type,token,user_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: nil,
				{Id: org1AT.PublicId}:   nil,
				{Id: org2AT.PublicId}:   nil,
			},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
				org1AT.PublicId:   {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
				org2AT.PublicId:   {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
			},
		},
		{
			name: "group user - global grant with auth-token type with read action can read all auth-tokens",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read;output_fields=id,authorized_actions,account_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: nil,
				{Id: org1AT.PublicId}:   nil,
				{Id: org2AT.PublicId}:   nil,
			},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.AuthorizedActionsField, globals.AccountIdField},
				org1AT.PublicId:   {globals.IdField, globals.AuthorizedActionsField, globals.AccountIdField},
				org2AT.PublicId:   {globals.IdField, globals.AuthorizedActionsField, globals.AccountIdField},
			},
		},
		{
			name: "ldap user - global grant with auth-token type with read action can read all auth-tokens",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read;output_fields=id,approximate_last_used_time"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: nil,
				{Id: org1AT.PublicId}:   nil,
				{Id: org2AT.PublicId}:   nil,
			},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.ApproximateLastUsedTimeField},
				org1AT.PublicId:   {globals.IdField, globals.ApproximateLastUsedTimeField},
				org2AT.PublicId:   {globals.IdField, globals.ApproximateLastUsedTimeField},
			},
		},
		{
			name: "oidc user - global grant with auth-token type with read action can read all auth-tokens",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: nil,
				{Id: org1AT.PublicId}:   nil,
				{Id: org2AT.PublicId}:   nil,
			},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField},
				org1AT.PublicId:   {globals.IdField},
				org2AT.PublicId:   {globals.IdField},
			},
		},
		{
			name: "org grant with this grant scope, auth-token type with read action returns all auth-tokens",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=auth-token;actions=read;output_fields=id,scope_id,type,token,user_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: handlers.ForbiddenError(),
				{Id: org1AT.PublicId}:   nil,
				{Id: org2AT.PublicId}:   handlers.ForbiddenError(),
			},
			expectOutfields: map[string][]string{
				org1AT.PublicId: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
			},
		},
		{
			name: "global grant with this grant scope, auth-token type with read action can read all auth-tokens",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read;output_fields=id,created_time,updated_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: nil,
				{Id: org1AT.PublicId}:   handlers.ForbiddenError(),
				{Id: org2AT.PublicId}:   handlers.ForbiddenError(),
			},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
			},
		},
		{
			name: "global grant with this grant scope, auth-token type with read actions returns all auth-tokens",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read;output_fields=id,scope_id,type,token,user_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: nil,
				{Id: org1AT.PublicId}:   handlers.ForbiddenError(),
				{Id: org2AT.PublicId}:   handlers.ForbiddenError(),
			},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
			},
		},
		{
			name: "global grant with this+children grant scope, with wildcard can read all auth-tokens",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: nil,
				{Id: org1AT.PublicId}:   nil,
				{Id: org2AT.PublicId}:   nil,
			},
			expectOutfields: map[string][]string{
				globalAT.PublicId: {globals.IdField, globals.ScopeIdField},
				org1AT.PublicId:   {globals.IdField, globals.ScopeIdField},
				org2AT.PublicId:   {globals.IdField, globals.ScopeIdField},
			},
		},
		{
			name: "org grant with children grant scope, auth-token type with read action cannot read auth-tokens",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=auth-token;actions=read"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: handlers.ForbiddenError(),
				{Id: org1AT.PublicId}:   handlers.ForbiddenError(),
				{Id: org2AT.PublicId}:   handlers.ForbiddenError(),
			},
		},
		{
			name: "global grant with non-applicable grant returns cannot read auth-tokens",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: handlers.ForbiddenError(),
				{Id: org1AT.PublicId}:   handlers.ForbiddenError(),
				{Id: org2AT.PublicId}:   handlers.ForbiddenError(),
			},
		},
		{
			name: "global grant with non-applicable action returns cannot read auth-tokens",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=list"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			inputWantErrMap: map[*pbs.GetAuthTokenRequest]error{
				{Id: globalAT.PublicId}: handlers.ForbiddenError(),
				{Id: org1AT.PublicId}:   handlers.ForbiddenError(),
				{Id: org2AT.PublicId}:   handlers.ForbiddenError(),
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
				got, err := s.GetAuthToken(fullGrantAuthCtx, input)
				if wantErr != nil {
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)

				item := got.GetItem()
				if item.GetId() != tok.GetPublicId() {
					if item.GetId() != tok.GetPublicId() {
						handlers.TestAssertOutputFields(t, item, tc.expectOutfields[item.GetId()])
					}
				}
			}
		})
	}
}

func TestGrants_ReadSelf(t *testing.T) {
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

	testcases := []struct {
		name            string
		userFunc        func() (user *iam.User, account auth.Account)
		wantErr         error
		expectOutfields []string
	}{
		{
			name: "direct user - global grant with auth-token type with read:self action can read auth-token",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read:self;output_fields=id,scope_id,type,token,user_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
		},
		{
			name: "group user - global grant with auth-token type with read:self action can read auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read:self;output_fields=id,authorized_actions,account_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.AuthorizedActionsField, globals.AccountIdField},
		},
		{
			name: "ldap user - global grant with auth-token type with read:self action can read auth-token",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read:self;output_fields=id,approximate_last_used_time"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.ApproximateLastUsedTimeField},
		},
		{
			name: "oidc user - global grant with auth-token type with read:self action can read auth-token",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read:self;output_fields=id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			expectOutfields: []string{globals.IdField},
		},
		{
			name: "global grant with this grant scope, auth-token type with read:self action can read auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read:self;output_fields=id,created_time,updated_time"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.CreatedTimeField, globals.UpdatedTimeField},
		},
		{
			name: "global grant with this grant scope, auth-token type with read:self actions returns auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=read:self;output_fields=id,scope_id,type,token,user_id"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.ScopeIdField, globals.TypeField, globals.AuthTokenIdField, globals.UserIdField},
		},
		{
			name: "global grant with this+children grant scope, with wildcard can read:self auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope_id"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			expectOutfields: []string{globals.IdField, globals.ScopeIdField},
		},
		{
			name: "org grant with children grant scope, auth-token type with read:self action cannot read auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=auth-token;actions=read:self"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			wantErr: handlers.ForbiddenError(),
		},
		{
			name: "global grant with non-applicable grant returns cannot read auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=read"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ForbiddenError(),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

			input := &pbs.GetAuthTokenRequest{Id: tok.GetPublicId()}
			got, err := s.GetAuthToken(fullGrantAuthCtx, input)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)

			item := got.GetItem()
			if item.GetId() != tok.GetPublicId() {
				if item.GetId() != tok.GetPublicId() {
					handlers.TestAssertOutputFields(t, item, tc.expectOutfields)
				}
			}
		})
	}
}

func TestGrants_Delete(t *testing.T) {
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

	testcases := []struct {
		name                    string
		userFunc                func() (user *iam.User, account auth.Account)
		deleteAllowedAtScopeIds []string
	}{
		{
			name: "direct user - global grant with auth-token type with delete action can delete auth-token",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			deleteAllowedAtScopeIds: []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId},
		},
		{
			name: "group user - global grant with auth-token type with delete action can delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			deleteAllowedAtScopeIds: []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId},
		},
		{
			name: "ldap user - global grant with auth-token type with delete action can delete auth-token",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			deleteAllowedAtScopeIds: []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId},
		},
		{
			name: "oidc user - global grant with auth-token type with delete action can delete auth-token",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			deleteAllowedAtScopeIds: []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId},
		},
		{
			name: "org grant with this grant scope, auth-token type with delete action can delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=auth-token;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			deleteAllowedAtScopeIds: []string{org1.PublicId},
		},
		{
			name: "global grant with this grant scope, auth-token type with delete action can delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			deleteAllowedAtScopeIds: []string{globals.GlobalPrefix},
		},
		{
			name: "global grant with this grant scope, auth-token type with delete actions returns can delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			deleteAllowedAtScopeIds: []string{globals.GlobalPrefix},
		},
		{
			name: "global grant with this+children grant scope, with wildcard can delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
			deleteAllowedAtScopeIds: []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId},
		},
		{
			name: "org grant with children grant scope, auth-token type with delete action cannot delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=auth-token;actions=delete"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			deleteAllowedAtScopeIds: []string{},
		},
		{
			name: "global grant with non-applicable grant returns cannot delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=delete"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			deleteAllowedAtScopeIds: []string{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			scopeIdGroupMap := map[string]*authtoken.AuthToken{}
			for _, scp := range []string{globals.GlobalPrefix, org1.PublicId, org2.PublicId} {
				authToken := authtoken.TestAuthToken(t, conn, kmsCache, scp)
				scopeIdGroupMap[scp] = authToken
			}

			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

			for scope, authToken := range scopeIdGroupMap {
				input := &pbs.DeleteAuthTokenRequest{Id: authToken.GetPublicId()}
				_, err := s.DeleteAuthToken(fullGrantAuthCtx, input)
				if !slices.Contains(tc.deleteAllowedAtScopeIds, scope) {
					require.ErrorIs(t, err, handlers.ForbiddenError())
					continue
				}
				require.NoErrorf(t, err, "failed to delete group in scope %s", scope)
			}
		})
	}
}

func TestGrants_DeleteSelf(t *testing.T) {
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

	testcases := []struct {
		name     string
		userFunc func() (user *iam.User, account auth.Account)
		wantErr  error
	}{
		{
			name: "direct user - global grant with auth-token type with delete:self action can delete auth-token",
			userFunc: iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete:self"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
		},
		{
			name: "group user - global grant with auth-token type with delete:self action can delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete:self"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
		},
		{
			name: "ldap user - global grant with auth-token type with delete:self action can delete auth-token",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete:self"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
		},
		{
			name: "oidc user - global grant with auth-token type with delete:self action can delete auth-token",
			userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete:self"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
		},
		{
			name: "global grant with this grant scope, auth-token type with delete:self action can delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete:self"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "global grant with this grant scope, auth-token type with delete:self actions returns auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=auth-token;actions=delete:self"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
		},
		{
			name: "global grant with this+children grant scope, with wildcard can delete:self auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=*;actions=*"},
					GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
				},
			}),
		},
		{
			name: "org grant with children grant scope, auth-token type with delete:self action cannot delete auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: org1.PublicId,
					Grants:      []string{"ids=*;type=auth-token;actions=delete:self"},
					GrantScopes: []string{globals.GrantScopeChildren},
				},
			}),
			wantErr: handlers.ForbiddenError(),
		},
		{
			name: "global grant with non-applicable grant returns cannot delete:self auth-token",
			userFunc: iam.TestUserGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAuthMethodWithAccount, []iam.TestRoleGrantsRequest{
				{
					RoleScopeId: globals.GlobalPrefix,
					Grants:      []string{"ids=*;type=group;actions=delete:self"},
					GrantScopes: []string{globals.GrantScopeThis},
				},
			}),
			wantErr: handlers.ForbiddenError(),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, account := tc.userFunc()
			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := cauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

			input := &pbs.DeleteAuthTokenRequest{Id: tok.GetPublicId()}
			_, err = s.DeleteAuthToken(fullGrantAuthCtx, input)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err, "failed to delete auth-token")
		})
	}
}
