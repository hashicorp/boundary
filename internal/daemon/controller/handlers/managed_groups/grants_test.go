// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package managed_groups_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/managed_groups"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

// TestGrants_ReadActions tests read actions to assert that grants are being applied properly
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	iamRepo := iam.TestRepo(t, conn, wrap)
	kmsCache := kms.TestKms(t, conn, wrap)
	oidcRepoFn := func() (*oidc.Repository, error) {
		// Use a small limit to test that membership lookup is explicitly unlimited
		return oidc.NewRepository(ctx, rw, rw, kmsCache, oidc.WithLimit(1))
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		// Use a small limit to test that membership lookup is explicitly unlimited
		return ldap.NewRepository(ctx, rw, rw, kmsCache, ldap.WithLimit(ctx, 1))
	}

	s, err := managed_groups.NewService(ctx, oidcRepoFn, ldapRepoFn, 1000)
	require.NoError(t, err)

	org, _ := iam.TestScopes(t, iamRepo)

	globalDBWrapper, err := kmsCache.GetWrapper(ctx, globals.GlobalPrefix, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	globalOidcAm := oidc.TestAuthMethod(
		t, conn, globalDBWrapper, globals.GlobalPrefix, oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	_ = oidc.TestAccount(t, conn, globalOidcAm, "test-subject-1", oidc.WithName("global-1"), oidc.WithDescription("global-1"))
	_ = oidc.TestAccount(t, conn, globalOidcAm, "test-subject-2", oidc.WithName("global-2"), oidc.WithDescription("global-2"))
	globalMg1 := oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter)
	globalMg2 := oidc.TestManagedGroup(t, conn, globalOidcAm, oidc.TestFakeManagedGroupFilter)

	orgDBWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	orgLdapAm := ldap.TestAuthMethod(t, conn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap1"}, ldap.WithName(ctx, "global"), ldap.WithDescription(ctx, "global"))
	_ = ldap.TestAccount(t, conn, orgLdapAm, "test-login-name-1", ldap.WithMemberOfGroups(ctx, "admin"), ldap.WithName(ctx, "org-1"), ldap.WithDescription(ctx, "org-1"))
	_ = ldap.TestAccount(t, conn, orgLdapAm, "test-login-name-2", ldap.WithMemberOfGroups(ctx, "admin"), ldap.WithName(ctx, "org-2"), ldap.WithDescription(ctx, "org-2"))
	orgMg := ldap.TestManagedGroup(t, conn, orgLdapAm, []string{"admin", "users"})

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name          string
			input         *pbs.ListManagedGroupsRequest
			rolesToCreate []authtoken.TestRoleGrantsForToken
			wantErr       error
			wantIDs       []string
		}{
			{
				name: "global role grant this returns all created oidc managed groups",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: globalOidcAm.PublicId,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				},
				wantErr: nil,
				wantIDs: []string{globalMg1.PublicId, globalMg2.PublicId},
			},
			{
				name: "org role grant this returns all created ldap managed groups",
				input: &pbs.ListManagedGroupsRequest{
					AuthMethodId: orgLdapAm.PublicId,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeID:  org.PublicId,
						GrantStrings: []string{"ids=*;type=managed-group;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				wantErr: nil,
				wantIDs: []string{
					orgMg.PublicId,
				},
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				got, finalErr := s.ListManagedGroups(fullGrantAuthCtx, tc.input)
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
