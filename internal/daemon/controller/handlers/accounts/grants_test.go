// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package accounts_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	pwstore "github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/accounts"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestListPassword_Grants(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo, err := iam.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}

	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}

	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrap))
	orgAM := password.TestAuthMethod(t, conn, org.GetPublicId())
	projAM := password.TestAuthMethod(t, conn, proj.GetPublicId())
	orgPWAccounts := password.TestMultipleAccounts(t, conn, orgAM.GetPublicId(), 3)
	projPWAccounts := password.TestMultipleAccounts(t, conn, projAM.GetPublicId(), 3)

	testcases := []struct {
		name           string
		roleRequest    []authtoken.TestRoleGrantsForToken
		input          *pbs.ListAccountsRequest
		wantAccountIDs []string
		wantErr        error
	}{
		{
			name: "children grants global scope list org accounts return org accounts",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: orgAM.PublicId,
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
				AuthMethodId: projAM.PublicId,
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
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
			require.NoError(t, err, "Couldn't create new user service.")
			tok := authtoken.TestAuthTokenWithRoles(t, conn, kms, globals.GlobalPrefix, tc.roleRequest)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, gErr := s.ListAccounts(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, gErr)
			require.Len(t, got.Items, len(orgPWAccounts))
			var gotIDs []string
			for _, item := range got.Items {
				gotIDs = append(gotIDs, item.Id)
			}
			require.ElementsMatch(t, tc.wantAccountIDs, gotIDs)
		})
	}
}

func TestGrants_GetAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	// not using OIDC or LDAP in this test so no need to set them up
	oidcRepoFn := func() (*oidc.Repository, error) {
		return &oidc.Repository{}, nil
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return &ldap.Repository{}, nil
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	globalPasswordAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	globalPWAccount := password.TestAccount(t, conn, globalPasswordAM.GetPublicId(), "global_name")

	org, _ := iam.TestScopes(t, iamRepo)
	orgAM := password.TestAuthMethod(t, conn, org.GetPublicId())
	orgPWAccount := password.TestAccount(t, conn, orgAM.GetPublicId(), "org_name")

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)

	testcases := []struct {
		name           string
		userAcountFunc func(t *testing.T) func() (*iam.User, string)
		input          *pbs.GetAccountRequest
		wantAccountID  string
		wantErr        error
	}{
		{
			name: "grant children at global can read account in org",
			input: &pbs.GetAccountRequest{
				Id: orgPWAccount.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			wantAccountID: orgPWAccount.PublicId,
			wantErr:       nil,
		},
		{
			name: "grant descendant at global cannot read global account",
			input: &pbs.GetAccountRequest{
				Id: globalPWAccount.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=read"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})
			},
			wantAccountID: "",
			wantErr:       handlers.ForbiddenError(),
		},
		{
			name: "grant this at global can read global account",
			input: &pbs.GetAccountRequest{
				Id: globalPWAccount.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantAccountID: globalPWAccount.PublicId,
			wantErr:       nil,
		},
		{
			name: "grant this at global cannot read org account",
			input: &pbs.GetAccountRequest{
				Id: orgPWAccount.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantAccountID: orgPWAccount.PublicId,
			wantErr:       nil,
		},
		{
			name: "grant this at org can read org account",
			input: &pbs.GetAccountRequest{
				Id: orgPWAccount.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantAccountID: orgPWAccount.PublicId,
			wantErr:       nil,
		},
		{
			name: "grant descendant with specific resource id can read org account",
			input: &pbs.GetAccountRequest{
				Id: orgPWAccount.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("id=%s;type=*;actions=read", orgAM.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			wantAccountID: orgPWAccount.PublicId,
			wantErr:       nil,
		},
		{
			name: "grant specific id but not scope global.This cannot read global account",
			input: &pbs.GetAccountRequest{
				Id: globalPWAccount.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("id=%s;type=*;actions=read", globalPasswordAM.PublicId)},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})
			},
			wantAccountID: "",
			wantErr:       handlers.ForbiddenError(),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, accountID := tc.userAcountFunc(t)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.GetAccount(fullGrantAuthCtx, tc.input)
			if tc.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantAccountID, got.Item.Id)
		})
	}
}

func TestGrants_CreateAccount(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	// not using OIDC or LDAP in this test so no need to set them up
	oidcRepoFn := func() (*oidc.Repository, error) {
		return &oidc.Repository{}, nil
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return &ldap.Repository{}, nil
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	org1 := iam.TestOrg(t, iamRepo)
	org2 := iam.TestOrg(t, iamRepo)

	globalAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	org1AM := password.TestAuthMethod(t, conn, org1.GetPublicId())
	org2AM := password.TestAuthMethod(t, conn, org2.GetPublicId())

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)

	testcases := []struct {
		name                     string
		userAcountFunc           func(t *testing.T) func() (*iam.User, string)
		authmethodIdExpectErrMap map[string]error
	}{
		{
			name: "grant this and descendant at global can create accounts everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and children at global can create accounts everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant children at global can create accounts in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant descendant at global can create accounts in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=*"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "pinned grant org1AM can only create accounts in org1AM",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=account;actions=create", org1AM.PublicId)},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
		{
			name: "grant auth-method type does not allow create account",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   handlers.ForbiddenError(),
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, accountID := tc.userAcountFunc(t)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for authMethodId, wantErr := range tc.authmethodIdExpectErrMap {
				loginName, _ := uuid.GenerateUUID()
				input := &pbs.CreateAccountRequest{
					Item: &pb.Account{
						AuthMethodId: authMethodId,
						Type:         "password",
						Attrs: &pb.Account_PasswordAccountAttributes{
							PasswordAccountAttributes: &pb.PasswordAccountAttributes{
								LoginName: loginName,
								Password:  nil,
							},
						},
					},
				}
				_, err := s.CreateAccount(fullGrantAuthCtx, input)
				if wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}

}

func TestGrants_DeleteAccount(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	// not using OIDC or LDAP in this test so no need to set them up
	oidcRepoFn := func() (*oidc.Repository, error) {
		return &oidc.Repository{}, nil
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return &ldap.Repository{}, nil
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	org1 := iam.TestOrg(t, iamRepo)
	org2 := iam.TestOrg(t, iamRepo)

	globalAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	org1AM := password.TestAuthMethod(t, conn, org1.GetPublicId())
	org2AM := password.TestAuthMethod(t, conn, org2.GetPublicId())

	allAuthMethodIds := []string{globalAM.PublicId, org1AM.PublicId, org2AM.PublicId}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name                     string
		userAcountFunc           func(t *testing.T) func() (*iam.User, string)
		authmethodIdExpectErrMap map[string]error
	}{
		{
			name: "grant this and descendant at global can delete accounts everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and children at global can delete accounts everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant children at global can delete accounts in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant descendant at global can delete accounts in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=delete"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and descendant at global with specific type and action can delete accounts in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=account;actions=delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "pinned grant org1AM can only delete accounts in org1AM",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=account;actions=delete", org1AM.PublicId)},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
		{
			name: "grant auth-method type does not allow delete create account",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   handlers.ForbiddenError(),
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			authMethodAccountMap := map[string]*password.Account{}
			for _, amid := range allAuthMethodIds {
				loginName, _ := uuid.GenerateUUID()
				acct := password.TestAccount(t, conn, amid, loginName)
				authMethodAccountMap[amid] = acct
			}
			user, accountID := tc.userAcountFunc(t)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for authMethodId, wantErr := range tc.authmethodIdExpectErrMap {
				_, err := s.DeleteAccount(fullGrantAuthCtx, &pbs.DeleteAccountRequest{
					Id: authMethodAccountMap[authMethodId].PublicId,
				})
				if wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}

}

func TestGrants_UpdateAccount(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	// not using OIDC or LDAP in this test so no need to set them up
	oidcRepoFn := func() (*oidc.Repository, error) {
		return &oidc.Repository{}, nil
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return &ldap.Repository{}, nil
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	org1 := iam.TestOrg(t, iamRepo)
	org2 := iam.TestOrg(t, iamRepo)

	globalAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	org1AM := password.TestAuthMethod(t, conn, org1.GetPublicId())
	org2AM := password.TestAuthMethod(t, conn, org2.GetPublicId())

	allAuthMethodIds := []string{globalAM.PublicId, org1AM.PublicId, org2AM.PublicId}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name                     string
		userAcountFunc           func(t *testing.T) func() (*iam.User, string)
		authmethodIdExpectErrMap map[string]error
	}{
		{
			name: "grant this and descendant at global can update accounts everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and children at global can update accounts everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant children at global can update accounts in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=update"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant descendant at global can update accounts in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=update"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and descendant at global with specific type and action can update accounts in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=account;actions=update"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "pinned grant org1AM can only update accounts in org1AM",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=account;actions=update", org1AM.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
		{
			name: "grant auth-method type does not allow update create account",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   handlers.ForbiddenError(),
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			authMethodAccountMap := map[string]*password.Account{}
			for _, amid := range allAuthMethodIds {
				loginName, _ := uuid.GenerateUUID()
				acct := password.TestAccount(t, conn, amid, loginName)
				authMethodAccountMap[amid] = acct
			}
			user, accountID := tc.userAcountFunc(t)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for authMethodId, wantErr := range tc.authmethodIdExpectErrMap {
				newName, _ := uuid.GenerateUUID()
				newDescription, _ := uuid.GenerateUUID()
				_, err := s.UpdateAccount(fullGrantAuthCtx, &pbs.UpdateAccountRequest{
					Id: authMethodAccountMap[authMethodId].PublicId,
					Item: &pb.Account{
						Name:        wrapperspb.String(newName),
						Description: wrapperspb.String(newDescription),
						Version:     1,
					},
					UpdateMask: &field_mask.FieldMask{
						Paths: []string{globals.NameField, globals.DescriptionField},
					},
				})
				if wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}

}

func TestGrants_SetPassword(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	// not using OIDC or LDAP in this test so no need to set them up
	oidcRepoFn := func() (*oidc.Repository, error) {
		return &oidc.Repository{}, nil
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return &ldap.Repository{}, nil
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	org1 := iam.TestOrg(t, iamRepo)
	org2 := iam.TestOrg(t, iamRepo)

	globalAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	org1AM := password.TestAuthMethod(t, conn, org1.GetPublicId())
	org2AM := password.TestAuthMethod(t, conn, org2.GetPublicId())

	allAuthMethodIds := []string{globalAM.PublicId, org1AM.PublicId, org2AM.PublicId}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name                     string
		userAcountFunc           func(t *testing.T) func() (*iam.User, string)
		authmethodIdExpectErrMap map[string]error
	}{
		{
			name: "grant this and descendant at global can set-password everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=set-password"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and children at global can set-password everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=set-password"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant children at global can set-password in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=set-password"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant descendant at global can set-password in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=set-password"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and descendant at global with specific type and action can set-password in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=account;actions=set-password"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "pinned grant org1AM can only set-password in org1AM",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=account;actions=set-password", org1AM.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
		{
			name: "grant auth-method type does not allow set-password",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   handlers.ForbiddenError(),
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			authMethodAccountMap := map[string]*password.Account{}
			for _, amid := range allAuthMethodIds {
				loginName, _ := uuid.GenerateUUID()
				acct := password.TestAccount(t, conn, amid, loginName)
				authMethodAccountMap[amid] = acct
			}
			user, accountID := tc.userAcountFunc(t)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for authMethodId, wantErr := range tc.authmethodIdExpectErrMap {
				pwd, _ := uuid.GenerateUUID()
				acct := authMethodAccountMap[authMethodId]
				_, err := s.SetPassword(fullGrantAuthCtx, &pbs.SetPasswordRequest{
					Id:       acct.PublicId,
					Version:  acct.Version,
					Password: pwd,
				})
				if wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}
func TestGrants_ChangePassword(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	pwRepo, err := password.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	pwRepoFn := func() (*password.Repository, error) {
		return pwRepo, nil
	}
	// not using OIDC or LDAP in this test so no need to set them up
	oidcRepoFn := func() (*oidc.Repository, error) {
		return &oidc.Repository{}, nil
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return &ldap.Repository{}, nil
	}
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	org1 := iam.TestOrg(t, iamRepo)
	org2 := iam.TestOrg(t, iamRepo)

	globalAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
	org1AM := password.TestAuthMethod(t, conn, org1.GetPublicId())
	org2AM := password.TestAuthMethod(t, conn, org2.GetPublicId())

	amIdsToScope := map[string]string{
		globalAM.PublicId: globals.GlobalPrefix,
		org1AM.PublicId:   org1.GetPublicId(),
		org2AM.PublicId:   org2.GetPublicId(),
	}

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)
	testcases := []struct {
		name                     string
		userAcountFunc           func(t *testing.T) func() (*iam.User, string)
		authmethodIdExpectErrMap map[string]error
	}{
		{
			name: "grant this and descendant at global can change-password everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=change-password"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and children at global can change-password everywhere",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=change-password"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant children at global can change-password in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserManagedGroupGrantsFunc(t, conn, kms, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kms, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=change-password"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant descendant at global can change-password in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=change-password"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "grant this and descendant at global with specific type and action can change-password in org",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=account;actions=change-password"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: nil,
				org1AM.PublicId:   nil,
				org2AM.PublicId:   nil,
			},
		},
		{
			name: "pinned grant org1AM can only change-password in org1AM",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=account;actions=change-password", org1AM.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   nil,
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
		{
			name: "grant auth-method type does not allow change-password",
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=auth-method;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				})
			},
			authmethodIdExpectErrMap: map[string]error{
				globalAM.PublicId: handlers.ForbiddenError(),
				org1AM.PublicId:   handlers.ForbiddenError(),
				org2AM.PublicId:   handlers.ForbiddenError(),
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			authMethodAccountMap := map[string]*password.Account{}
			for amID, scopeID := range amIdsToScope {
				loginName, _ := uuid.GenerateUUID()
				// use repo.CreateAccount instead of `password.TestAccount` because
				// the test version does not set the password even with the password.WithPassword option
				acct, err := pwRepo.CreateAccount(context.Background(), scopeID, &password.Account{
					Account: &pwstore.Account{
						AuthMethodId: amID,
						LoginName:    loginName,
					},
				}, password.WithPassword("oldpassword"))
				require.NoError(t, err)
				authMethodAccountMap[amID] = acct
			}
			user, accountID := tc.userAcountFunc(t)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
			require.NoError(t, err)
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			for authMethodId, wantErr := range tc.authmethodIdExpectErrMap {
				newpassword, _ := uuid.GenerateUUID()
				testAcct := authMethodAccountMap[authMethodId]
				_, err := s.ChangePassword(fullGrantAuthCtx, &pbs.ChangePasswordRequest{
					Id:              testAcct.PublicId,
					Version:         testAcct.Version,
					CurrentPassword: "oldpassword",
					NewPassword:     newpassword,
				})
				if wantErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, wantErr)
					continue
				}
				require.NoErrorf(t, err, "failed at authMethodId %s", authMethodId)
			}
		})
	}

}

func TestGrants_OutputFields(t *testing.T) {
	t.Run("GetAccounts", func(t *testing.T) {
		ctx := context.TODO()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		pwRepo, err := password.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		pwRepoFn := func() (*password.Repository, error) {
			return pwRepo, nil
		}

		oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		oidcRepoFn := func() (*oidc.Repository, error) {
			return oidcRepo, nil
		}

		ldapRepo, err := ldap.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		ldapRepoFn := func() (*ldap.Repository, error) {
			return ldapRepo, nil
		}

		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)

		// only testing global to reduce the permutations and mostly because we're only testing the output fields
		// grants behavior for walking down the scope tree should be tested in the other tests
		passwordAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
		passwordAccount, err := pwRepo.CreateAccount(context.Background(), globals.GlobalPrefix, &password.Account{
			Account: &pwstore.Account{
				AuthMethodId: passwordAM.PublicId,
				LoginName:    "globalname",
				Name:         "globalname",
				Description:  "globaldesc",
			},
		})
		require.NoError(t, err)

		ldapAM := ldap.TestAuthMethod(t, conn, wrap, globals.GlobalPrefix, []string{"ldap://test"})
		_ = ldap.TestManagedGroup(t, conn, ldapAM, []string{"ldap"})
		ldapAccount := ldap.TestAccount(t, conn, ldapAM, "ldapname", ldap.WithName(ctx, "ldapname"), ldap.WithDescription(ctx, "ldapdesc"), ldap.WithMemberOfGroups(ctx, "ldap"))

		databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		oidcAM := oidc.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePublicState,
			"alice-rp", "fido",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://bob.com")[0]),
			oidc.WithSigningAlgs(oidc.Alg(oidc.RS256)),
			oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://bob.com/callback")[0]))

		oidcAccount := oidc.TestAccount(t, conn, oidcAM, "oidcreadacct", oidc.WithName("oidcreadname"), oidc.WithDescription("oidcreaddesc"))
		oidcManagedGroup := oidc.TestManagedGroup(t, conn, oidcAM, `"/token/sub" matches ".*"`)
		_ = oidc.TestManagedGroupMember(t, conn, oidcManagedGroup.PublicId, oidcAccount.PublicId)

		s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
		require.NoError(t, err)

		testcases := []struct {
			name            string
			userAcountFunc  func(t *testing.T) func() (*iam.User, string)
			input           *pbs.GetAccountRequest
			expectOutfields []string
		}{
			{
				name: "password account all output fields",
				input: &pbs.GetAccountRequest{
					Id: passwordAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "password account id,name,scope,description output fields",
				input: &pbs.GetAccountRequest{
					Id: passwordAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name: "password account created_time,updated_time,version,type output fields",
				input: &pbs.GetAccountRequest{
					Id: passwordAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name: "password account auth_method_id,attributes,authorized_actions output fields",
				input: &pbs.GetAccountRequest{
					Id: passwordAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "ldap account all output fields",
				input: &pbs.GetAccountRequest{
					Id: ldapAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"ldap_account_attributes",
					globals.AuthorizedActionsField,
					globals.ManagedGroupIdsField,
				},
			},
			{
				name: "ldap account id,scope,name,description output fields",
				input: &pbs.GetAccountRequest{
					Id: ldapAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name: "ldap account created_time,updated_time,version,type output fields",
				input: &pbs.GetAccountRequest{
					Id: ldapAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name: "ldap account auth_method_id,attributes,authorized_actions,managed_group_ids output fields",
				input: &pbs.GetAccountRequest{
					Id: ldapAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions,managed_group_ids"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"ldap_account_attributes",
					globals.AuthorizedActionsField,
					globals.ManagedGroupIdsField,
				},
			},
			{
				name: "oidc account all output fields",
				input: &pbs.GetAccountRequest{
					Id: oidcAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"oidc_account_attributes",
					globals.AuthorizedActionsField,
					globals.ManagedGroupIdsField,
				},
			},
			{
				name: "oidc account id,scope,name,description output fields",
				input: &pbs.GetAccountRequest{
					Id: oidcAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name: "oidc account created_time,updated_time,version,type output fields",
				input: &pbs.GetAccountRequest{
					Id: oidcAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name: "oidc account auth_method_id,attributes,authorized_actions,managed_group_ids output fields",
				input: &pbs.GetAccountRequest{
					Id: oidcAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions,managed_group_ids"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"oidc_account_attributes",
					globals.AuthorizedActionsField,
					globals.ManagedGroupIdsField,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userAcountFunc(t)()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.GetAccount(fullGrantAuthCtx, tc.input)
				require.NoError(t, err)
				handlers.AssertOutputFields(t, got.GetItem(), tc.expectOutfields)
			})
		}

	})
	t.Run("CreateAccount", func(t *testing.T) {
		ctx := context.TODO()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		pwRepo, err := password.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		pwRepoFn := func() (*password.Repository, error) {
			return pwRepo, nil
		}

		oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		oidcRepoFn := func() (*oidc.Repository, error) {
			return oidcRepo, nil
		}

		ldapRepo, err := ldap.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		ldapRepoFn := func() (*ldap.Repository, error) {
			return ldapRepo, nil
		}

		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)

		passwordAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
		require.NoError(t, err)
		ldapAM := ldap.TestAuthMethod(t, conn, wrap, globals.GlobalPrefix, []string{"ldap://test"})
		_ = ldap.TestManagedGroup(t, conn, ldapAM, []string{"ldap"})

		databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		oidcAM := oidc.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePublicState,
			"alice-rp", "fido",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://bob.com")[0]),
			oidc.WithSigningAlgs(oidc.Alg(oidc.RS256)),
			oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://bob.com/callback")[0]))

		s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
		require.NoError(t, err)

		globalScopeInfo := &scopes.ScopeInfo{
			Id:            scope.Global.String(),
			Type:          scope.Global.String(),
			Name:          scope.Global.String(),
			Description:   "Global Scope",
			ParentScopeId: "",
		}

		genPasswordRequest := func(t *testing.T) *pbs.CreateAccountRequest {
			name, err := uuid.GenerateUUID()
			require.NoError(t, err)
			item := &pb.Account{
				Scope:        globalScopeInfo,
				Name:         wrapperspb.String(name),
				Description:  wrapperspb.String(name),
				AuthMethodId: passwordAM.PublicId,
				Type:         "password",
				Attrs: &pb.Account_PasswordAccountAttributes{
					PasswordAccountAttributes: &pb.PasswordAccountAttributes{
						LoginName: name,
						Password:  wrapperspb.String("pwalloutput"),
					},
				},
			}
			return &pbs.CreateAccountRequest{
				Item: item,
			}
		}

		genLdapRequest := func(t *testing.T) *pbs.CreateAccountRequest {
			name, err := uuid.GenerateUUID()
			require.NoError(t, err)
			item := &pb.Account{
				Scope:        globalScopeInfo,
				Name:         wrapperspb.String(name),
				Description:  wrapperspb.String(name),
				AuthMethodId: ldapAM.PublicId,
				Type:         "ldap",
				Attrs: &pb.Account_LdapAccountAttributes{
					LdapAccountAttributes: &pb.LdapAccountAttributes{
						LoginName: name,
					},
				},
			}
			return &pbs.CreateAccountRequest{
				Item: item,
			}
		}

		genOidcRequest := func(t *testing.T) *pbs.CreateAccountRequest {
			name, err := uuid.GenerateUUID()
			require.NoError(t, err)
			item := &pb.Account{
				Scope:        globalScopeInfo,
				Name:         wrapperspb.String(name),
				Description:  wrapperspb.String(name),
				AuthMethodId: oidcAM.PublicId,
				Type:         "oidc",
				Attrs: &pb.Account_OidcAccountAttributes{
					OidcAccountAttributes: &pb.OidcAccountAttributes{
						Issuer:         oidcAM.Issuer,
						Subject:        name,
						TokenClaims:    &structpb.Struct{},
						UserinfoClaims: &structpb.Struct{},
					},
				},
			}
			return &pbs.CreateAccountRequest{
				Item: item,
			}
		}

		testcases := []struct {
			name            string
			userAcountFunc  func(t *testing.T) func() (*iam.User, string)
			input           func(t *testing.T) *pbs.CreateAccountRequest
			expectOutfields []string
		}{
			{
				name:  "password account all output fields",
				input: genPasswordRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name:  "password account id,name,scope,description output fields",
				input: genPasswordRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name:  "password account created_time,updated_time,version,type output fields",
				input: genPasswordRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name:  "password account auth_method_id,attributes,authorized_actions output fields",
				input: genPasswordRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name:  "ldap account all output fields",
				input: genLdapRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"ldap_account_attributes",
					globals.AuthorizedActionsField,
					// ManagedGroupIdsField is not returned in the output fields because it's set outside of the CreateAccount call
					// so at the time of CreateAccount, this list will always return nil
					// globals.ManagedGroupIdsField,
				},
			},
			{
				name:  "ldap account id,scope,name,description output fields",
				input: genLdapRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name:  "ldap account created_time,updated_time,version,type output fields",
				input: genLdapRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name:  "ldap account auth_method_id,attributes,authorized_actions,managed_group_ids output fields",
				input: genLdapRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions,managed_group_ids"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"ldap_account_attributes",
					globals.AuthorizedActionsField,
					// globals.ManagedGroupIdsField,
				},
			},
			{
				name:  "oidc account all output fields",
				input: genOidcRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"oidc_account_attributes",
					globals.AuthorizedActionsField,
					// ManagedGroupIdsField is not returned in the output fields because it's set outside of the CreateAccount call
					// so at the time of CreateAccount, this list will always return nil
					// globals.ManagedGroupIdsField,
				},
			},
			{
				name:  "oidc account id,scope,name,description output fields",
				input: genOidcRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name:  "oidc account created_time,updated_time,version,type output fields",
				input: genOidcRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name:  "oidc account auth_method_id,attributes,authorized_actions,managed_group_ids output fields",
				input: genOidcRequest,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions,managed_group_ids"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"oidc_account_attributes",
					globals.AuthorizedActionsField,
					// ManagedGroupIdsField is not returned in the output fields because it's set outside of the CreateAccount call
					// so at the time of CreateAccount, this list will always return nil
					// globals.ManagedGroupIdsField,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userAcountFunc(t)()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.CreateAccount(fullGrantAuthCtx, tc.input(t))
				require.NoError(t, err)
				handlers.AssertOutputFields(t, got.GetItem(), tc.expectOutfields)
			})
		}

	})
	t.Run("GetAccounts", func(t *testing.T) {
		ctx := context.TODO()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		pwRepo, err := password.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		pwRepoFn := func() (*password.Repository, error) {
			return pwRepo, nil
		}

		oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		oidcRepoFn := func() (*oidc.Repository, error) {
			return oidcRepo, nil
		}

		ldapRepo, err := ldap.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		ldapRepoFn := func() (*ldap.Repository, error) {
			return ldapRepo, nil
		}

		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)

		// only testing global to reduce the permutations and mostly because we're only testing the output fields
		// grants behavior for walking down the scope tree should be tested in the other tests
		passwordAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
		passwordAccount, err := pwRepo.CreateAccount(context.Background(), globals.GlobalPrefix, &password.Account{
			Account: &pwstore.Account{
				AuthMethodId: passwordAM.PublicId,
				LoginName:    "globalname",
				Name:         "globalname",
				Description:  "globaldesc",
			},
		})
		require.NoError(t, err)

		ldapAM := ldap.TestAuthMethod(t, conn, wrap, globals.GlobalPrefix, []string{"ldap://test"})
		_ = ldap.TestManagedGroup(t, conn, ldapAM, []string{"ldap"})
		ldapAccount := ldap.TestAccount(t, conn, ldapAM, "ldapname", ldap.WithName(ctx, "ldapname"), ldap.WithDescription(ctx, "ldapdesc"), ldap.WithMemberOfGroups(ctx, "ldap"))

		databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		oidcAM := oidc.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePublicState,
			"alice-rp", "fido",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://bob.com")[0]),
			oidc.WithSigningAlgs(oidc.Alg(oidc.RS256)),
			oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://bob.com/callback")[0]))

		oidcAccount := oidc.TestAccount(t, conn, oidcAM, "oidcreadacct", oidc.WithName("oidcreadname"), oidc.WithDescription("oidcreaddesc"))
		oidcManagedGroup := oidc.TestManagedGroup(t, conn, oidcAM, `"/token/sub" matches ".*"`)
		_ = oidc.TestManagedGroupMember(t, conn, oidcManagedGroup.PublicId, oidcAccount.PublicId)

		s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
		require.NoError(t, err)

		testcases := []struct {
			name            string
			userAcountFunc  func(t *testing.T) func() (*iam.User, string)
			input           *pbs.GetAccountRequest
			expectOutfields []string
		}{
			{
				name: "password account all output fields",
				input: &pbs.GetAccountRequest{
					Id: passwordAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "password account id,name,scope,description output fields",
				input: &pbs.GetAccountRequest{
					Id: passwordAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name: "password account created_time,updated_time,version,type output fields",
				input: &pbs.GetAccountRequest{
					Id: passwordAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name: "password account auth_method_id,attributes,authorized_actions output fields",
				input: &pbs.GetAccountRequest{
					Id: passwordAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name: "ldap account all output fields",
				input: &pbs.GetAccountRequest{
					Id: ldapAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"ldap_account_attributes",
					globals.AuthorizedActionsField,
					globals.ManagedGroupIdsField,
				},
			},
			{
				name: "ldap account id,scope,name,description output fields",
				input: &pbs.GetAccountRequest{
					Id: ldapAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name: "ldap account created_time,updated_time,version,type output fields",
				input: &pbs.GetAccountRequest{
					Id: ldapAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name: "ldap account auth_method_id,attributes,authorized_actions,managed_group_ids output fields",
				input: &pbs.GetAccountRequest{
					Id: ldapAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions,managed_group_ids"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"ldap_account_attributes",
					globals.AuthorizedActionsField,
					globals.ManagedGroupIdsField,
				},
			},
			{
				name: "oidc account all output fields",
				input: &pbs.GetAccountRequest{
					Id: oidcAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"oidc_account_attributes",
					globals.AuthorizedActionsField,
					globals.ManagedGroupIdsField,
				},
			},
			{
				name: "oidc account id,scope,name,description output fields",
				input: &pbs.GetAccountRequest{
					Id: oidcAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name: "oidc account created_time,updated_time,version,type output fields",
				input: &pbs.GetAccountRequest{
					Id: oidcAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name: "oidc account auth_method_id,attributes,authorized_actions,managed_group_ids output fields",
				input: &pbs.GetAccountRequest{
					Id: oidcAccount.PublicId,
				},
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions,managed_group_ids"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"oidc_account_attributes",
					globals.AuthorizedActionsField,
					globals.ManagedGroupIdsField,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userAcountFunc(t)()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.GetAccount(fullGrantAuthCtx, tc.input)
				require.NoError(t, err)
				handlers.AssertOutputFields(t, got.GetItem(), tc.expectOutfields)
			})
		}

	})
	t.Run("UpdateAccount", func(t *testing.T) {
		ctx := context.TODO()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		pwRepo, err := password.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		pwRepoFn := func() (*password.Repository, error) {
			return pwRepo, nil
		}

		oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		oidcRepoFn := func() (*oidc.Repository, error) {
			return oidcRepo, nil
		}

		ldapRepo, err := ldap.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		ldapRepoFn := func() (*ldap.Repository, error) {
			return ldapRepo, nil
		}

		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)

		passwordInputFunc := func(t *testing.T) *pbs.UpdateAccountRequest {
			id, err := uuid.GenerateUUID()
			require.NoError(t, err)
			passwordAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
			passwordAccount, err := pwRepo.CreateAccount(context.Background(), globals.GlobalPrefix, &password.Account{
				Account: &pwstore.Account{
					AuthMethodId: passwordAM.PublicId,
					LoginName:    strings.ReplaceAll(id, "-", ""),
					Name:         id,
					Description:  id,
				},
			})
			require.NoError(t, err)
			return &pbs.UpdateAccountRequest{
				Id: passwordAccount.PublicId,
				Item: &pb.Account{
					Description: wrapperspb.String("test"),
					Version:     passwordAccount.Version,
				},
				UpdateMask: &fieldmaskpb.FieldMask{
					Paths: []string{"description"},
				},
			}
		}

		ldapInputFunc := func(t *testing.T) *pbs.UpdateAccountRequest {
			id, err := uuid.GenerateUUID()
			require.NoError(t, err)
			ldapAM := ldap.TestAuthMethod(t, conn, wrap, globals.GlobalPrefix, []string{"ldap://" + id})
			_ = ldap.TestManagedGroup(t, conn, ldapAM, []string{id})
			ldapAccount := ldap.TestAccount(t, conn, ldapAM, strings.ReplaceAll(id, "-", ""), ldap.WithName(ctx, id), ldap.WithDescription(ctx, id), ldap.WithMemberOfGroups(ctx, id))
			return &pbs.UpdateAccountRequest{
				Id: ldapAccount.PublicId,
				Item: &pb.Account{
					Description: wrapperspb.String("test"),
					Version:     ldapAccount.Version,
				},
				UpdateMask: &fieldmaskpb.FieldMask{
					Paths: []string{"description"},
				},
			}
		}

		oidcInputFunc := func(t *testing.T) *pbs.UpdateAccountRequest {
			id, err := uuid.GenerateUUID()
			require.NoError(t, err)
			databaseWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
			require.NoError(t, err)
			oidcAM := oidc.TestAuthMethod(t, conn, databaseWrapper, globals.GlobalPrefix, oidc.ActivePublicState,
				"alice-rp", "fido",
				oidc.WithIssuer(oidc.TestConvertToUrls(t, fmt.Sprintf("https://%s.com", id))[0]),
				oidc.WithSigningAlgs(oidc.Alg(oidc.RS256)),
				oidc.WithApiUrl(oidc.TestConvertToUrls(t, fmt.Sprintf("https://%s.com/callback", id))[0]))

			oidcAccount := oidc.TestAccount(t, conn, oidcAM, id, oidc.WithName(id), oidc.WithDescription(id))
			oidcManagedGroup := oidc.TestManagedGroup(t, conn, oidcAM, `"/token/sub" matches ".*"`)
			_ = oidc.TestManagedGroupMember(t, conn, oidcManagedGroup.PublicId, oidcAccount.PublicId)
			return &pbs.UpdateAccountRequest{
				Id: oidcAccount.PublicId,
				Item: &pb.Account{
					Description: wrapperspb.String("test"),
					Version:     oidcAccount.Version,
				},
				UpdateMask: &fieldmaskpb.FieldMask{
					Paths: []string{"description"},
				},
			}
		}
		s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
		require.NoError(t, err)

		testcases := []struct {
			name            string
			userAcountFunc  func(t *testing.T) func() (*iam.User, string)
			input           func(t *testing.T) *pbs.UpdateAccountRequest
			expectOutfields []string
		}{
			{
				name:  "password account all output fields",
				input: passwordInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name:  "password account id,name,scope,description output fields",
				input: passwordInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name:  "password account created_time,updated_time,version,type output fields",
				input: passwordInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name:  "password account auth_method_id,attributes,authorized_actions output fields",
				input: passwordInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name:  "ldap account all output fields",
				input: ldapInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"ldap_account_attributes",
					globals.AuthorizedActionsField,
					// ManagedGroupIdsField is not returned in the output fields because it's set outside of the CreateAccount call
					// so at the time of CreateAccount, this list will always return nil
					// globals.ManagedGroupIdsField,
				},
			},
			{
				name:  "ldap account id,scope,name,description output fields",
				input: ldapInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name:  "ldap account created_time,updated_time,version,type output fields",
				input: ldapInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name:  "ldap account auth_method_id,attributes,authorized_actions,managed_group_ids output fields",
				input: ldapInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions,managed_group_ids"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"ldap_account_attributes",
					globals.AuthorizedActionsField,
					// globals.ManagedGroupIdsField,
				},
			},
			{
				name:  "oidc account all output fields",
				input: oidcInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"oidc_account_attributes",
					globals.AuthorizedActionsField,
					// ManagedGroupIdsField is not returned in the output fields because it's set outside of the CreateAccount call
					// so at the time of CreateAccount, this list will always return nil
					// globals.ManagedGroupIdsField,
				},
			},
			{
				name:  "oidc account id,scope,name,description output fields",
				input: oidcInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name:  "oidc account created_time,updated_time,version,type output fields",
				input: oidcInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name:  "oidc account auth_method_id,attributes,authorized_actions,managed_group_ids output fields",
				input: oidcInputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, oidc.TestAccountFunc(t, conn, kmsCache, globals.GlobalPrefix), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions,managed_group_ids"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"oidc_account_attributes",
					globals.AuthorizedActionsField,
					// ManagedGroupIdsField is not returned in the output fields because it's set outside of the CreateAccount call
					// so at the time of CreateAccount, this list will always return nil
					// globals.ManagedGroupIdsField,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userAcountFunc(t)()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.UpdateAccount(fullGrantAuthCtx, tc.input(t))
				require.NoError(t, err)
				handlers.AssertOutputFields(t, got.GetItem(), tc.expectOutfields)
			})
		}

	})

	// only test password accounts since SetPassword is only available for password accounts
	t.Run("SetPassword", func(t *testing.T) {
		ctx := context.TODO()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		pwRepo, err := password.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		pwRepoFn := func() (*password.Repository, error) {
			return pwRepo, nil
		}

		oidcRepoFn := func() (*oidc.Repository, error) {
			return &oidc.Repository{}, nil
		}

		ldapRepoFn := func() (*ldap.Repository, error) {
			return &ldap.Repository{}, nil
		}

		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)

		inputFunc := func(t *testing.T) *pbs.SetPasswordRequest {
			id, err := uuid.GenerateUUID()
			require.NoError(t, err)
			passwordAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
			passwordAccount, err := pwRepo.CreateAccount(context.Background(), globals.GlobalPrefix, &password.Account{
				Account: &pwstore.Account{
					AuthMethodId: passwordAM.PublicId,
					LoginName:    strings.ReplaceAll(id, "-", ""),
					Name:         id,
					Description:  id,
				},
			})
			require.NoError(t, err)
			return &pbs.SetPasswordRequest{
				Id:       passwordAccount.GetPublicId(),
				Version:  passwordAccount.GetVersion(),
				Password: id,
			}
		}

		s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
		require.NoError(t, err)

		testcases := []struct {
			name            string
			userAcountFunc  func(t *testing.T) func() (*iam.User, string)
			input           func(t *testing.T) *pbs.SetPasswordRequest
			expectOutfields []string
		}{
			{
				name:  "password account all output fields",
				input: inputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name:  "password account id,name,scope,description output fields",
				input: inputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name:  "password account created_time,updated_time,version,type output fields",
				input: inputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name:  "password account auth_method_id,attributes,authorized_actions output fields",
				input: inputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userAcountFunc(t)()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.SetPassword(fullGrantAuthCtx, tc.input(t))
				require.NoError(t, err)
				handlers.AssertOutputFields(t, got.GetItem(), tc.expectOutfields)
			})
		}

	})

	// only test password accounts since SetPassword is only available for password accounts
	t.Run("ChangePassword", func(t *testing.T) {
		ctx := context.TODO()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		wrap := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, wrap)
		iamRepo := iam.TestRepo(t, conn, wrap)
		pwRepo, err := password.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)
		pwRepoFn := func() (*password.Repository, error) {
			return pwRepo, nil
		}

		oidcRepoFn := func() (*oidc.Repository, error) {
			return &oidc.Repository{}, nil
		}

		ldapRepoFn := func() (*ldap.Repository, error) {
			return &ldap.Repository{}, nil
		}

		atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
		require.NoError(t, err)

		inputFunc := func(t *testing.T) *pbs.ChangePasswordRequest {
			id, err := uuid.GenerateUUID()
			require.NoError(t, err)
			passwordAM := password.TestAuthMethod(t, conn, globals.GlobalPrefix)
			passwordAccount, err := pwRepo.CreateAccount(context.Background(), globals.GlobalPrefix, &password.Account{
				Account: &pwstore.Account{
					AuthMethodId: passwordAM.PublicId,
					LoginName:    strings.ReplaceAll(id, "-", ""),
					Name:         id,
					Description:  id,
				},
			}, password.WithPassword("oldpassword"))
			require.NoError(t, err)
			return &pbs.ChangePasswordRequest{
				Id:              passwordAccount.GetPublicId(),
				Version:         passwordAccount.GetVersion(),
				CurrentPassword: "oldpassword",
				NewPassword:     "newpassword",
			}
		}

		s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
		require.NoError(t, err)

		testcases := []struct {
			name            string
			userAcountFunc  func(t *testing.T) func() (*iam.User, string)
			input           func(t *testing.T) *pbs.ChangePasswordRequest
			expectOutfields []string
		}{
			{
				name:  "password account all output fields",
				input: inputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=*"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
			{
				name:  "password account id,name,scope,description output fields",
				input: inputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=id,scope,name,description"},
						},
					})
				},
				expectOutfields: []string{
					globals.IdField,
					globals.ScopeField,
					globals.NameField,
					globals.DescriptionField,
				},
			},
			{
				name:  "password account created_time,updated_time,version,type output fields",
				input: inputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=created_time,updated_time,version,type"},
						},
					})
				},
				expectOutfields: []string{
					globals.CreatedTimeField,
					globals.UpdatedTimeField,
					globals.VersionField,
					globals.TypeField,
				},
			},
			{
				name:  "password account auth_method_id,attributes,authorized_actions output fields",
				input: inputFunc,
				userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
					return iam.TestUserDirectGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
						{
							RoleScopeID: globals.GlobalPrefix,
							GrantScopes: []string{globals.GrantScopeThis},
							Grants:      []string{"ids=*;type=*;actions=*;output_fields=auth_method_id,attributes,authorized_actions"},
						},
					})
				},
				expectOutfields: []string{
					globals.AuthMethodIdField,
					"password_account_attributes", // this needs to be manually filled for each type because each subtype represents different field names
					globals.AuthorizedActionsField,
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, accountID := tc.userAcountFunc(t)()
				tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
				require.NoError(t, err)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, err := s.ChangePassword(fullGrantAuthCtx, tc.input(t))
				require.NoError(t, err)
				handlers.AssertOutputFields(t, got.GetItem(), tc.expectOutfields)
			})
		}

	})

}
