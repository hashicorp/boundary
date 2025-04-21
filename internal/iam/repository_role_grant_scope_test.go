// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/stretchr/testify/require"
)

func Test_AddRoleGrantScopes(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := TestRepo(t, conn, wrap)
	testcases := []struct {
		name             string
		roleScopeId      string
		grantScopesToAdd []string
		want             []RoleGrantScope
		wantErr          error
	}{
		{
			name:             "",
			grantScopesToAdd: []string{"this", "descendants"},
			want: []RoleGrantScope{
				{
					CreateTime:       nil,
					RoleId:           "",
					ScopeIdOrSpecial: "",
				},
			},
			wantErr: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			role := TestRole(t, conn, tc.roleScopeId, WithGrantScopeIds([]string{"testing-none"}))
			got, err := iamRepo.AddRoleGrantScopes(ctx, role.PublicId, role.Version, tc.grantScopesToAdd)
			require.NoError(t, err)
			require.NotNil(t, got)
			roleAfter, _, _, _, err := iamRepo.LookupRole(ctx, role.PublicId)
			require.NoError(t, err)
			require.Equal(t, role.Version+1, roleAfter.Version)
		})
	}
}

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
		wantErr     error
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
			wantErr: nil,
		},
		{
			name: "multiple roles with different grants union grants happy path",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				firstRole := TestRole(t, conn, globals.GlobalPrefix)
				secondRole := TestRole(t, conn, org2.PublicId)

				firstRoleOrg1 := &GlobalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
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

				secondRoleProj2 := &GlobalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
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
						ScopeIdOrSpecial: proj1.PublicId,
					},
					{
						RoleId:           secondRole.PublicId,
						ScopeIdOrSpecial: proj2.PublicId,
					},
				}
			},
			wantErr: nil,
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
			wantErr: nil,
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
			got, err := iamRepo.ListRoleGrantScopes(ctx, roleIds)
			require.NoError(t, err)
			gotRoleScopeMap := roleScopesToMap(t, got)
			require.Equal(t, len(expectRoleScopeMap), len(gotRoleScopeMap))
			for roleId, expectRoleScopes := range expectRoleScopeMap {
				gotRoleScopes, found := gotRoleScopeMap[roleId]
				require.True(t, found)
				fmt.Println(gotRoleScopes)
				fmt.Println(expectRoleScopes)
				require.ElementsMatch(t, expectRoleScopes, gotRoleScopes)
			}
		})
	}
}

func roleScopesToMap(t *testing.T, roleGrantScopes []*RoleGrantScope) map[string][]string {
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

func assertRoleGrantScope(t *testing.T, expect, got RoleGrantScope) {
	require.Equal(t, expect.RoleId, got.RoleId)
	require.Equal(t, expect.ScopeIdOrSpecial, got.ScopeIdOrSpecial)
	require.NotNil(t, got.CreateTime)

}
