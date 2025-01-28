// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package accounts_test

import (
	"context"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

func TestListPassword_Grants(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	testKMS := kms.TestKms(t, conn, wrap)
	iamRepo, err := iam.NewRepository(ctx, rw, rw, testKMS)
	require.NoError(t, err)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, testKMS)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, testKMS)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, testKMS)
	}

	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	// password accounts
	globalPasswordAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	orgPasswordAM := password.TestAuthMethod(t, conn, org.GetPublicId())
	projPasswordAM := password.TestAuthMethod(t, conn, proj.GetPublicId())
	globalPWAccounts := password.TestMultipleAccounts(t, conn, globalPasswordAM.GetPublicId(), 3)
	orgPWAccounts := password.TestMultipleAccounts(t, conn, orgPasswordAM.GetPublicId(), 3)
	projPWAccounts := password.TestMultipleAccounts(t, conn, projPasswordAM.GetPublicId(), 3)

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name           string
			roleRequest    []authtoken.TestRoleGrantsForToken
			input          *pbs.ListAccountsRequest
			wantAccountIDs []string
			wantErr        error
		}{
			{
				name: "grants this and descendant global scope list org accounts return org accounts",
				input: &pbs.ListAccountsRequest{
					AuthMethodId: globalPasswordAM.GetPublicId(),
					PageSize:     100,
				},
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeDescendants},
					},
				},
				wantAccountIDs: []string{globalPWAccounts[0].PublicId, globalPWAccounts[1].PublicId, globalPWAccounts[2].PublicId},
				wantErr:        nil,
			},
			{
				name: "children grants global scope list org accounts return org accounts",
				input: &pbs.ListAccountsRequest{
					AuthMethodId: orgPasswordAM.GetPublicId(),
					PageSize:     100,
				},
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				wantAccountIDs: []string{orgPWAccounts[0].PublicId, orgPWAccounts[1].PublicId, orgPWAccounts[2].PublicId},
				wantErr:        nil,
			},
			{
				name: "children grants org scope list project accounts return project accounts",
				input: &pbs.ListAccountsRequest{
					AuthMethodId: projPasswordAM.PublicId,
					PageSize:     100,
				},
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  org.GetPublicId(),
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				wantAccountIDs: []string{projPWAccounts[0].PublicId, projPWAccounts[1].PublicId, projPWAccounts[2].PublicId},
				wantErr:        nil,
			},
			{
				name: "children grants org scope list project accounts return project accounts",
				input: &pbs.ListAccountsRequest{
					AuthMethodId: projPasswordAM.PublicId,
					PageSize:     100,
				},
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  org.GetPublicId(),
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				wantAccountIDs: []string{projPWAccounts[0].PublicId, projPWAccounts[1].PublicId, projPWAccounts[2].PublicId},
				wantErr:        nil,
			},
			{
				name: "grant this and children at global scope list at project returns forbidden error",
				input: &pbs.ListAccountsRequest{
					AuthMethodId: projPasswordAM.PublicId,
					PageSize:     100,
				},
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeChildren},
					},
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantAccountIDs: nil,
				wantErr:        handlers.ForbiddenError(),
			},
			{
				name: "grant only descendant at global listing global project returns forbidden error",
				input: &pbs.ListAccountsRequest{
					AuthMethodId: globalPasswordAM.GetPublicId(),
					PageSize:     100,
				},
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeDescendants},
					},
				},
				wantAccountIDs: nil,
				wantErr:        handlers.ForbiddenError(),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
				require.NoError(t, err, "Couldn't create new user service.")
				tok := authtoken.TestAuthTokenWithRoles(t, conn, testKMS, globals.GlobalPrefix, tc.roleRequest)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.ListAccounts(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				require.Len(t, got.Items, len(orgPWAccounts))
				var gotIDs []string
				for _, item := range got.Items {
					gotIDs = append(gotIDs, item.Id)
				}
				require.ElementsMatch(t, tc.wantAccountIDs, gotIDs)
			})
		}
	})
	t.Run("Get", func(t *testing.T) {
		// IDToExpect represents individual testcase idToExpects ID being passed into "GetAccount" call
		// to the expected error
		type IDToExpect struct {
			id  string
			err error
		}

		testcases := []struct {
			name        string
			roleRequest []authtoken.TestRoleGrantsForToken
			// map of account ID to expected error when listing
			idToExpects []IDToExpect
		}{
			{
				name: "grants this and descendant global scope list org accounts return no error",
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeDescendants},
					},
				},
				idToExpects: []IDToExpect{
					{
						id:  globalPWAccounts[0].PublicId,
						err: nil,
					},
					{
						id:  orgPWAccounts[0].PublicId,
						err: nil,
					},
					{
						id:  projPWAccounts[0].PublicId,
						err: nil,
					},
				},
			},
			{
				name: "grants children at global can only get org accounts",
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeChildren},
					},
				},
				idToExpects: []IDToExpect{
					{
						id:  globalPWAccounts[0].PublicId,
						err: handlers.ForbiddenError(),
					},
					{
						id:  orgPWAccounts[0].PublicId,
						err: nil,
					},
					{
						id:  projPWAccounts[0].PublicId,
						err: handlers.ForbiddenError(),
					},
				},
			},
			{
				name: "additive grants returns correct access",
				roleRequest: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
					{
						RoleScopeID:  org.GetPublicId(),
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
					{
						RoleScopeID:  proj.GetPublicId(),
						GrantStrings: []string{"ids=*;type=*;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				idToExpects: []IDToExpect{
					{
						id:  globalPWAccounts[0].PublicId,
						err: nil,
					},
					{
						id:  orgPWAccounts[0].PublicId,
						err: nil,
					},
					{
						id:  projPWAccounts[0].PublicId,
						err: nil,
					},
				},
			},
			{
				name: "no grants all returns error",
				idToExpects: []IDToExpect{
					{
						id:  globalPWAccounts[0].PublicId,
						err: handlers.ForbiddenError(),
					},
					{
						id:  orgPWAccounts[0].PublicId,
						err: handlers.ForbiddenError(),
					},
					{
						id:  projPWAccounts[0].PublicId,
						err: handlers.ForbiddenError(),
					},
				},
				roleRequest: []authtoken.TestRoleGrantsForToken{},
			},
			{
				name: "no grants all returns error",
				idToExpects: []IDToExpect{
					{
						id:  globalPWAccounts[0].PublicId,
						err: handlers.ForbiddenError(),
					},
					{
						id:  orgPWAccounts[0].PublicId,
						err: handlers.ForbiddenError(),
					},
					{
						id:  projPWAccounts[0].PublicId,
						err: handlers.ForbiddenError(),
					},
				},
				roleRequest: []authtoken.TestRoleGrantsForToken{},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
				require.NoError(t, err, "Couldn't create new user service.")
				tok := authtoken.TestAuthTokenWithRoles(t, conn, testKMS, globals.GlobalPrefix, tc.roleRequest)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for _, idToError := range tc.idToExpects {
					_, err := s.GetAccount(fullGrantAuthCtx, &pbs.GetAccountRequest{
						Id: idToError.id,
					})
					if idToError.err != nil {
						require.Error(t, err)
						require.ErrorIs(t, err, idToError.err)
						continue
					}
					require.NoError(t, err)
				}

			})
		}
	})

}
