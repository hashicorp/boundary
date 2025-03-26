// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package roles_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/roles"
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
//			- project level
//		Grant - what IAM grant scope is set for the permission
//			- global: descendant
//			- org: children
//			- project
//		Scopes [resource]:
//			- global [globalRole]
//				- org1 [org1Role]
//					- proj1 [proj1Role]
//				- org2 [org2Role]
//					- proj2 [proj2Role]
//					- proj3 [proj3Role]
func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	kmsCache := kms.TestKms(t, conn, wrap)
	s, err := roles.NewService(ctx, repoFn, 1000)
	require.NoError(t, err)

	org1, _ := iam.TestScopes(t, iamRepo)
	org2, proj2 := iam.TestScopes(t, iamRepo)
	proj3 := iam.TestProject(t, iamRepo, org2.PublicId)

	var defaultOrg1Roles []string
	org1Roles, err := s.ListRoles(auth.DisabledAuthTestContext(repoFn, org1.GetPublicId()), &pbs.ListRolesRequest{
		ScopeId: org1.GetPublicId(),
	})
	require.NoError(t, err)
	for _, r := range org1Roles.Items {
		defaultOrg1Roles = append(defaultOrg1Roles, r.GetId())
	}

	org2Roles, err := s.ListRoles(auth.DisabledAuthTestContext(repoFn, org2.GetPublicId()), &pbs.ListRolesRequest{
		ScopeId: org2.GetPublicId(),
	})
	require.NoError(t, err)
	var defaultOrg2Roles []string
	for _, r := range org2Roles.Items {
		defaultOrg2Roles = append(defaultOrg2Roles, r.GetId())
	}

	proj2Roles, err := s.ListRoles(auth.DisabledAuthTestContext(repoFn, proj2.GetPublicId()), &pbs.ListRolesRequest{
		ScopeId: proj2.GetPublicId(),
	})
	require.NoError(t, err)
	var defaultProj2Roles []string
	for _, r := range proj2Roles.Items {
		defaultProj2Roles = append(defaultProj2Roles, r.GetId())
	}

	proj3Roles, err := s.ListRoles(auth.DisabledAuthTestContext(repoFn, proj3.GetPublicId()), &pbs.ListRolesRequest{
		ScopeId: proj3.GetPublicId(),
	})
	require.NoError(t, err)
	var defaultProj3Roles []string
	for _, r := range proj3Roles.Items {
		defaultProj3Roles = append(defaultProj3Roles, r.GetId())
	}

	org1Role := iam.TestRole(t, conn, org1.GetPublicId(), iam.WithDescription("org1"), iam.WithName("org1"))
	org2Role := iam.TestRole(t, conn, org2.GetPublicId(), iam.WithDescription("org2"), iam.WithName("org2"))

	proj2Role := iam.TestRole(t, conn, proj2.GetPublicId(), iam.WithDescription("proj2"), iam.WithName("proj2"))
	proj3Role := iam.TestRole(t, conn, proj3.GetPublicId(), iam.WithDescription("proj3"), iam.WithName("proj3"))

	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name                string
			input               *pbs.ListRolesRequest
			rolesToCreate       []authtoken.TestRoleGrantsForToken
			wantErr             error
			addRolesAtThisScope bool
			wantIDs             []string
		}{
			{
				name: "global role grant this and children returns global and org roles",
				input: &pbs.ListRolesRequest{
					ScopeId:   globals.GlobalPrefix,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  globals.GlobalPrefix,
						GrantStrings: []string{"ids=*;type=role;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				addRolesAtThisScope: true,
				wantErr:             nil,
				wantIDs: append(append([]string{
					org1Role.PublicId,
					org2Role.PublicId,
				}, defaultOrg1Roles...), defaultOrg2Roles...),
			},
			{
				name: "org role grant this and children returns org and project roles",
				input: &pbs.ListRolesRequest{
					ScopeId:   org2.PublicId,
					Recursive: true,
				},
				rolesToCreate: []authtoken.TestRoleGrantsForToken{
					{
						RoleScopeId:  org2.PublicId,
						GrantStrings: []string{"ids=*;type=role;actions=list,read"},
						GrantScopes:  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				},
				addRolesAtThisScope: true,
				wantErr:             nil,
				wantIDs: append(append([]string{
					proj2Role.PublicId,
					proj3Role.PublicId,
				}, defaultProj2Roles...), defaultProj3Roles...),
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				tok := authtoken.TestAuthTokenWithRoles(t, conn, kmsCache, globals.GlobalPrefix, tc.rolesToCreate)
				fullGrantAuthCtx := auth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				// TestAuthTokenWithRoles creates a default role, so we need to add it to the expected list
				// if the grant scope contains 'this'
				// This will add the default roles to the expected list of roles
				if tc.addRolesAtThisScope {
					var rolesAtThisScope []string
					rolesAtThisScopeList, err := s.ListRoles(auth.DisabledAuthTestContext(repoFn, tc.input.ScopeId), &pbs.ListRolesRequest{
						ScopeId: tc.input.ScopeId,
					})
					require.NoError(t, err)
					for _, r := range rolesAtThisScopeList.Items {
						rolesAtThisScope = append(rolesAtThisScope, r.GetId())
					}
					tc.wantIDs = append(tc.wantIDs, rolesAtThisScope...)
				}

				got, finalErr := s.ListRoles(fullGrantAuthCtx, tc.input)
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
