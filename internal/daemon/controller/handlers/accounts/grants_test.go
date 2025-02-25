// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package accounts_test

import (
	"context"
	"fmt"
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
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGrants_ListAccounts(t *testing.T) {
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
	globalPWAccounts := password.TestMultipleAccounts(t, conn, globalPasswordAM.GetPublicId(), 3)

	org, _ := iam.TestScopes(t, iamRepo)
	orgAM := password.TestAuthMethod(t, conn, org.GetPublicId())
	orgPWAccounts := password.TestMultipleAccounts(t, conn, orgAM.GetPublicId(), 3)

	s, err := accounts.NewService(ctx, pwRepoFn, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)

	testcases := []struct {
		name           string
		userAcountFunc func(t *testing.T) func() (*iam.User, string)
		input          *pbs.ListAccountsRequest
		wantAccountIDs []string
		wantErr        error
	}{
		{
			name: "grant children at global can list org accounts",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: orgAM.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			wantAccountIDs: []string{orgPWAccounts[0].PublicId, orgPWAccounts[1].PublicId, orgPWAccounts[2].PublicId},
			wantErr:        nil,
		},
		{
			name: "grant children at global cannot list global accounts",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: globalPasswordAM.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
			},
			wantAccountIDs: nil,
			wantErr:        handlers.ForbiddenError(),
		},
		{
			name: "grant this at global can list global accounts",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: globalPasswordAM.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantAccountIDs: []string{globalPWAccounts[0].PublicId, globalPWAccounts[1].PublicId, globalPWAccounts[2].PublicId},
			wantErr:        nil,
		},
		{
			name: "grant this at global cannot list org accounts",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: orgAM.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{"ids=*;type=*;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantAccountIDs: nil,
			wantErr:        handlers.ForbiddenError(),
		},
		{
			name: "grant this at org can list org accounts",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: orgAM.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: org.PublicId,
						Grants:      []string{"ids=*;type=*;actions=list,read"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantAccountIDs: []string{orgPWAccounts[0].PublicId, orgPWAccounts[1].PublicId, orgPWAccounts[2].PublicId},
			wantErr:        nil,
		},
		{
			name: "grant specific resource type can list account",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: orgAM.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: org.PublicId,
						Grants:      []string{"ids=*;type=account;actions=list,no-op"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
			},
			wantAccountIDs: []string{orgPWAccounts[0].PublicId, orgPWAccounts[1].PublicId, orgPWAccounts[2].PublicId},
			wantErr:        nil,
		},
		{
			name: "grant pinned grants can list account",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: orgAM.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=*;actions=read,list,no-op", orgAM.PublicId)},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})
			},
			wantAccountIDs: []string{orgPWAccounts[0].PublicId, orgPWAccounts[1].PublicId, orgPWAccounts[2].PublicId},
			wantErr:        nil,
		},
		{
			name: "grant pinned grants cannot list account that is not the pinned ID",
			input: &pbs.ListAccountsRequest{
				AuthMethodId: globalPasswordAM.PublicId,
			},
			userAcountFunc: func(t *testing.T) func() (*iam.User, string) {
				return iam.TestUserDirectGrantsFunc(t, conn, kms, globals.GlobalPrefix, password.TestAccountFunc(t, conn), []iam.TestRoleGrantsRequest{
					{
						RoleScopeID: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;type=*;actions=read,list,no-op", orgAM.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				})
			},
			wantAccountIDs: nil,
			wantErr:        handlers.ForbiddenError(),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			user, accountID := tc.userAcountFunc(t)()
			tok, err := atRepo.CreateAuthToken(ctx, user, accountID)
			require.NoError(t, err)
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
						Name:        &wrapperspb.StringValue{Value: newName},
						Description: &wrapperspb.StringValue{Value: newDescription},
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

}
