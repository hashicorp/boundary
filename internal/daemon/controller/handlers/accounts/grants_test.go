// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package accounts_test

import (
	"context"
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
					RoleScopeId:  globals.GlobalPrefix,
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
					RoleScopeId:  org.GetPublicId(),
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
			fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, iamRepo, tok)

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
