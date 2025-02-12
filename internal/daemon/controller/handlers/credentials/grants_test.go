// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentials_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentials"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
//
//	 Role - which scope the role is created in
//			- global level
//			- org level
//			- proj level
//		Grant - what IAM grant scope is set for the permission
//			- global: descendant
//			- org: children
//			- project: this
//		Scopes [resource]:
//			- global
//				- org1
//					- proj1
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsCache)
	}
	s, err := credentials.NewService(ctx, iamRepoFn, staticRepoFn, 1000)
	require.NoError(t, err)

	org, proj := iam.TestScopes(t, iamRepo)

	credStore := static.TestCredentialStore(t, conn, wrap, proj.GetPublicId())
	var wantCreds []string
	for i := 0; i < 10; i++ {
		user := fmt.Sprintf("user-%d", i)
		pass := fmt.Sprintf("pass-%d", i)
		c := static.TestUsernamePasswordCredential(t, conn, wrap, user, pass, credStore.GetPublicId(), proj.GetPublicId())
		require.NoError(t, err)
		wantCreds = append(wantCreds, c.GetPublicId())
	}

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			input         *pbs.ListCredentialsRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
			wantIDs       []string
		}{
			{
				name: "global role grant this returns all created credentials",
				input: &pbs.ListCredentialsRequest{
					CredentialStoreId: credStore.GetPublicId(),
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=credential;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: nil,
				wantIDs: wantCreds,
			},
			{
				name: "org role grant this returns all created credentials",
				input: &pbs.ListCredentialsRequest{
					CredentialStoreId: credStore.GetPublicId(),
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  org.PublicId,
						GrantStrings: []string{"ids=*;type=credential;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: wantCreds,
			},
			{
				name: "project role grant this returns all created credentials",
				input: &pbs.ListCredentialsRequest{
					CredentialStoreId: credStore.GetPublicId(),
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  proj.PublicId,
						GrantStrings: []string{"ids=*;type=credential;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis},
					},
				},
				wantErr: nil,
				wantIDs: wantCreds,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListCredentials(fullGrantAuthCtx, tc.input)
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
}
