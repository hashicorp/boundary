// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/stretchr/testify/require"
)

func Test_LookupRoleScope(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := TestRepo(t, conn, wrap)
	rw := db.New(conn)

	org1, proj1 := TestScopes(t, iamRepo)
	org2, proj2 := TestScopes(t, iamRepo)

	testcases := []struct {
		name string
		// setup function that return []*Role that will be used as test input and list of expected RoleGrantScope
		setupExpect func(t *testing.T) ([]*Role, []*RoleGrantScope)
		wantErr     bool
		wantErrMsg  string
	}{
		{
			name: "global role no individual scope grants happy path",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				r := TestRole(t, conn, globals.GlobalPrefix)
				gRole := allocGlobalRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))
				gRole.GrantScope = globals.GrantScopeDescendants
				_, err := rw.Update(ctx, &gRole, []string{"GrantScope"}, []string{})
				require.NoError(t, err)
				return []*Role{r}, []*RoleGrantScope{
					{
						RoleId:           r.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeDescendants,
					},
					{
						RoleId:           r.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "global role without this happy path",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				r := TestRole(t, conn, globals.GlobalPrefix)
				gRole := allocGlobalRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))
				gRole.GrantThisRoleScope = false
				gRole.GrantScope = globals.GrantScopeDescendants
				_, err := rw.Update(ctx, &gRole, []string{"GrantScope", "GrantThisRoleScope"}, []string{})
				require.NoError(t, err)
				return []*Role{r}, []*RoleGrantScope{
					{
						RoleId:           r.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeDescendants,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "global role without any grants return empty",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				r := TestRole(t, conn, globals.GlobalPrefix)
				gRole := allocGlobalRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))
				gRole.GrantThisRoleScope = false
				_, err := rw.Update(ctx, &gRole, []string{"GrantThisRoleScope"}, []string{})
				require.NoError(t, err)
				return []*Role{r}, []*RoleGrantScope{}
			},
			wantErr: false,
		},
		{
			name: "multiple roles with different grants union grants happy path",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				firstRole := TestRole(t, conn, globals.GlobalPrefix)
				secondRole := TestRole(t, conn, org2.PublicId)

				firstRoleOrg1 := &GlobalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     firstRole.PublicId,
						ScopeId:    org1.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, firstRoleOrg1))
				firstRoleProj1 := &GlobalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     firstRole.PublicId,
						ScopeId:    proj1.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, firstRoleProj1))

				secondRoleProj2 := &OrgRoleIndividualGrantScope{
					OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
						RoleId:     secondRole.PublicId,
						ScopeId:    proj2.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, secondRoleProj2))

				return []*Role{firstRole, secondRole}, []*RoleGrantScope{
					{
						RoleId:           firstRole.PublicId,
						ScopeIdOrSpecial: org1.PublicId,
					},
					{
						RoleId:           firstRole.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
					{
						RoleId:           firstRole.PublicId,
						ScopeIdOrSpecial: proj1.PublicId,
					},
					{
						RoleId:           secondRole.PublicId,
						ScopeIdOrSpecial: proj2.PublicId,
					},
					{
						RoleId:           secondRole.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "global role with individual scope grants happy path",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				r := TestRole(t, conn, globals.GlobalPrefix)
				gRole := allocGlobalRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))
				o1 := &GlobalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org1.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, o1))
				o2 := &GlobalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org2.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, o2))
				p1 := &GlobalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj1.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, p1))
				p2 := &GlobalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj2.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, p2))
				return []*Role{r}, []*RoleGrantScope{
					{
						RoleId:           r.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
					{
						RoleId:           r.PublicId,
						ScopeIdOrSpecial: org1.PublicId,
					},
					{
						RoleId:           r.PublicId,
						ScopeIdOrSpecial: org2.PublicId,
					},
					{
						RoleId:           r.PublicId,
						ScopeIdOrSpecial: proj1.PublicId,
					},
					{
						RoleId:           r.PublicId,
						ScopeIdOrSpecial: proj2.PublicId,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "multiple role with children and descendants grants happy path",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				role1 := TestRole(t, conn, globals.GlobalPrefix)
				role2 := TestRole(t, conn, org2.PublicId)

				gRole := allocGlobalRole()
				gRole.PublicId = role1.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))
				gRole.GrantScope = globals.GrantScopeDescendants
				_, err := rw.Update(ctx, &gRole, []string{"GrantScope"}, []string{})
				require.NoError(t, err)

				oRole := allocOrgRole()
				oRole.PublicId = role2.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &oRole))
				oRole.GrantScope = globals.GrantScopeChildren
				_, err = rw.Update(ctx, &oRole, []string{"GrantScope"}, []string{})
				require.NoError(t, err)

				return []*Role{role1, role2}, []*RoleGrantScope{
					{
						RoleId:           role1.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
					{
						RoleId:           role1.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeDescendants,
					},
					{
						RoleId:           role2.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
					{
						RoleId:           role2.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeChildren,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "multiple project role happy path",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				role1 := TestRole(t, conn, proj1.PublicId)
				role2 := TestRole(t, conn, proj2.PublicId)
				return []*Role{role1, role2}, []*RoleGrantScope{
					{
						RoleId:           role1.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
					{
						RoleId:           role2.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "role does not exist returns empty grant scope",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				invalidRole := &Role{
					PublicId: "r_123456",
					ScopeId:  globals.GlobalPrefix,
				}
				return []*Role{invalidRole}, []*RoleGrantScope{}
			},
			wantErr: false,
		},
		{
			name: "bad role id returns error",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				invalidRole := &Role{
					PublicId: "",
					ScopeId:  globals.GlobalPrefix,
				}
				return []*Role{invalidRole}, []*RoleGrantScope{}
			},
			wantErr:    true,
			wantErrMsg: `iam.(Repository).listRoleGrantScopes: missing role ids: parameter violation: error #100`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			roles, expect := tc.setupExpect(t)
			var roleIds []string
			for _, r := range roles {
				roleIds = append(roleIds, r.PublicId)
			}
			expectRoleScopeMap := roleScopesToMap(t, expect)
			got, err := listRoleGrantScopes(ctx, rw, roleIds)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			require.NoError(t, err)
			gotRoleScopeMap := roleScopesToMap(t, got)
			require.Equal(t, len(expectRoleScopeMap), len(gotRoleScopeMap))
			for roleId, expectRoleScopes := range expectRoleScopeMap {
				gotRoleScopes, found := gotRoleScopeMap[roleId]
				require.True(t, found)
				require.ElementsMatch(t, expectRoleScopes, gotRoleScopes)
			}
		})
	}
}

func roleScopesToMap(t *testing.T, roleGrantScopes []*RoleGrantScope) map[string][]string {
	t.Helper()
	m := map[string][]string{}
	for _, e := range roleGrantScopes {
		scopes, ok := m[e.RoleId]
		if !ok {
			m[e.RoleId] = []string{e.ScopeIdOrSpecial}
			continue
		}
		m[e.RoleId] = append(scopes, e.ScopeIdOrSpecial)
	}
	return m
}
