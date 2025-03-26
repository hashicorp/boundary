// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentiallibraries_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentiallibraries"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/require"
)

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
	sche := scheduler.TestScheduler(t, conn, wrap)

	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, rw, rw, kmsCache, sche)
	}

	s, err := credentiallibraries.NewService(ctx, iamRepoFn, vaultRepoFn, 1000)
	require.NoError(t, err)
	org, proj := iam.TestScopes(t, iamRepo)

	proj1CredStore := vault.TestCredentialStores(t, conn, wrap, proj.PublicId, 1)
	proj1Libs := vault.TestCredentialLibraries(t, conn, wrap, proj1CredStore[0].GetPublicId(), 3)

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			input         *pbs.ListCredentialLibrariesRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
			wantIDs       []string
		}{
			{
				name: "global role grant descendant returns all credentials library",
				input: &pbs.ListCredentialLibrariesRequest{
					CredentialStoreId: proj1CredStore[0].GetPublicId(),
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=credential-library;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: nil,
				wantIDs: []string{proj1Libs[0].GetPublicId(), proj1Libs[1].GetPublicId(), proj1Libs[2].GetPublicId()},
			},
			{
				name: "org role grant this and children returns all credentials library",
				input: &pbs.ListCredentialLibrariesRequest{
					CredentialStoreId: proj1CredStore[0].GetPublicId(),
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  org.GetPublicId(),
						GrantStrings: []string{"ids=*;type=credential-library;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: []string{proj1Libs[0].GetPublicId(), proj1Libs[1].GetPublicId(), proj1Libs[2].GetPublicId()},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListCredentialLibraries(fullGrantAuthCtx, tc.input)
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
