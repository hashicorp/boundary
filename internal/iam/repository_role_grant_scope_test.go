// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_listRoleGrantScopes(t *testing.T) {
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

				firstRoleOrg1 := &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     firstRole.PublicId,
						ScopeId:    org1.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, firstRoleOrg1))
				firstRoleProj1 := &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     firstRole.PublicId,
						ScopeId:    proj1.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, firstRoleProj1))

				secondRoleProj2 := &orgRoleIndividualGrantScope{
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
				o1 := &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org1.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, o1))
				o2 := &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org2.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, o2))
				p1 := &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj1.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
				require.NoError(t, rw.Create(ctx, p1))
				p2 := &globalRoleIndividualProjectGrantScope{
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
			name: "project role with this grant",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				role := TestRole(t, conn, proj1.PublicId)
				return []*Role{role}, []*RoleGrantScope{
					{
						RoleId:           role.PublicId,
						ScopeIdOrSpecial: globals.GrantScopeThis,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "project role without this grant",
			setupExpect: func(t *testing.T) ([]*Role, []*RoleGrantScope) {
				role := TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{"testing-none"}))
				return []*Role{role}, []*RoleGrantScope{}
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
				return []*Role{}, []*RoleGrantScope{}
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

func Test_AddRoleGrantScope(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := TestRepo(t, conn, wrap)

	org1, proj1 := TestScopes(t, iamRepo)
	org2, proj2 := TestScopes(t, iamRepo)

	testcases := []struct {
		name                  string
		setupRole             func(t *testing.T) *Role
		inputAddScopes        []string // this is both the input and expect
		wantReturnedScopes    []string // this is the expected scopes that are added (input scopes minus existing grant scopes)
		wantRoleVersionChange uint32
		wantScopes            []string // this is always validated even in error case
		wantErr               bool
		wantErrMsg            string
	}{
		{
			name: "global role add all individual grant scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix)
			},
			inputAddScopes:        []string{proj1.PublicId, proj2.PublicId, org1.PublicId, org2.PublicId},
			wantReturnedScopes:    []string{org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId},
			wantRoleVersionChange: 1,
			wantScopes:            []string{globals.GrantScopeThis, org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId},
			wantErr:               false,
		},
		{
			name: "global role dedupe individual scope",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org1.PublicId, proj1.PublicId}))
			},
			inputAddScopes:        []string{org1.PublicId, proj1.PublicId},
			wantReturnedScopes:    []string{},
			wantRoleVersionChange: 0,
			wantScopes:            []string{org1.PublicId, proj1.PublicId},
			wantErr:               false,
		},
		{
			name: "global role add this, children. and individual project",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{"testing-none"}))
			},
			inputAddScopes:        []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId},
			wantReturnedScopes:    []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId},
			wantRoleVersionChange: 1,
			wantScopes:            []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId},
			wantErr:               false,
		},
		{
			name: "global role add dedupe special scope",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId}))
			},
			inputAddScopes:        []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId},
			wantReturnedScopes:    []string{},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId},
			wantErr:               false,
		},
		{
			name: "global role add individual scope when grant_scope is children",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
			},
			inputAddScopes:        []string{proj1.PublicId},
			wantReturnedScopes:    []string{proj1.PublicId},
			wantRoleVersionChange: 1,
			wantScopes:            []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId},
			wantErr:               false,
		},
		{
			name: "global role error adding conflicting grants when individual scope exists",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{proj1.PublicId}))
			},
			inputAddScopes:        []string{globals.GrantScopeDescendants},
			wantRoleVersionChange: 0,
			wantScopes:            []string{proj1.PublicId},
			wantErr:               true,
			wantErrMsg:            "iam.(Repository).AddRoleGrantScopes: db.DoTx: iam.(Repository).AddRoleGrantScopes: unable to update role: db.Update: only_individual_or_children_grant_scope_allowed constraint failed: check constraint violated: integrity violation: error #1000",
		},
		{
			name: "global role error adding overlapping grants",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org1.PublicId}))
			},
			inputAddScopes:        []string{globals.GrantScopeChildren},
			wantRoleVersionChange: 0,
			wantScopes:            []string{org1.PublicId},
			wantErr:               true,
			wantErrMsg:            "iam.(Repository).AddRoleGrantScopes: db.DoTx: iam.(Repository).AddRoleGrantScopes: unable to update role: db.Update: immutable column: iam_role_global_individual_org_grant_scope.grant_scope: integrity violation: error #1003",
		},
		{
			name: "global role error adding children when descendants already exists",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeChildren}))
			},
			inputAddScopes:        []string{globals.GrantScopeDescendants},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeChildren},
			wantErr:               true,
			wantErrMsg:            "iam.(Repository).AddRoleGrantScopes: grant scope children already exists, only one of descendants or children grant scope can be specified: parameter violation: error #100",
		},
		{
			name: "global role error adding descendants when children already exists",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeDescendants}))
			},
			inputAddScopes:        []string{globals.GrantScopeChildren},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeDescendants},
			wantErr:               true,
			wantErrMsg:            "iam.(Repository).AddRoleGrantScopes: grant scope descendants already exists, only one of descendants or children grant scope can be specified: parameter violation: error #100",
		},
		{
			name: "global role error adding mutually exclusive grants",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{"testing-none"}))
			},
			inputAddScopes:        []string{globals.GrantScopeChildren, globals.GrantScopeDescendants},
			wantRoleVersionChange: 0,
			wantScopes:            []string{},
			wantErr:               true,
			wantErrMsg:            "iam.(Repository).AddRoleGrantScopes: only one of descendants or children grant scope can be specified: parameter violation: error #100",
		},
		{
			name: "global role error adding overlapping grants",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{"testing-none"}))
			},
			inputAddScopes:        []string{globals.GrantScopeDescendants, proj1.PublicId},
			wantRoleVersionChange: 0,
			wantScopes:            []string{},
			wantErr:               true,
			wantErrMsg:            "iam.(Repository).AddRoleGrantScopes: db.DoTx: iam.(Repository).AddRoleGrantScopes: unable to add individual project grant scopes for global role: db.CreateItems: only_individual_or_children_grant_scope_allowed constraint failed: check constraint violated: integrity violation: error #1000",
		},
		{
			name: "org role add specials",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{"testing-none"}))
			},
			inputAddScopes:        []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantReturnedScopes:    []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantRoleVersionChange: 1,
			wantScopes:            []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantErr:               false,
		},
		{
			name: "org role add individual",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId)
			},
			inputAddScopes:        []string{proj1.PublicId},
			wantReturnedScopes:    []string{proj1.PublicId},
			wantRoleVersionChange: 1,
			wantScopes:            []string{globals.GrantScopeThis, proj1.PublicId},
			wantErr:               false,
		},
		{
			name: "org role dedupe individual",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{proj1.PublicId}))
			},
			inputAddScopes:        []string{proj1.PublicId},
			wantReturnedScopes:    []string{},
			wantRoleVersionChange: 0,
			wantScopes:            []string{proj1.PublicId},
			wantErr:               false,
		},
		{
			name: "org role dedupe special",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
			},
			inputAddScopes:        []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantReturnedScopes:    []string{},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantErr:               false,
		},
		{
			name: "org role error adding invalid grants",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeChildren}))
			},
			inputAddScopes:        []string{globals.GrantScopeDescendants},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeChildren},
			wantErr:               true,
			wantErrMsg:            `iam.(Repository).AddRoleGrantScopes: grant scope children already exists, only one of descendants or children grant scope can be specified: parameter violation: error #100`,
		},
		{
			name: "org role error adding overlapping grants",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeChildren}))
			},
			inputAddScopes:        []string{proj1.PublicId},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeChildren},
			wantErr:               true,
			wantErrMsg:            `iam.(Repository).AddRoleGrantScopes: db.DoTx: iam.(Repository).AddRoleGrantScopes: unable to add individual project grant scopes for global role: db.CreateItems: insert or update on table "iam_role_org_individual_grant_scope" violates foreign key constraint "iam_role_org_grant_scope_fkey": integrity violation: error #1003`,
		},
		{
			name: "org role error adding project not belong to this org",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId)
			},
			inputAddScopes:        []string{proj2.PublicId},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeThis},
			wantErr:               true,
			wantErrMsg:            fmt.Sprintf(`iam.(Repository).AddRoleGrantScopes: db.DoTx: iam.(Repository).AddRoleGrantScopes: unable to add individual project grant scopes for global role: db.CreateItems: project scope_id %s not found in org: integrity violation: error #1104`, proj2.PublicId),
		},
		{
			name: "project role add this grant_scope",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{"testing-none"}))
			},
			inputAddScopes:        []string{globals.GrantScopeThis},
			wantReturnedScopes:    []string{globals.GrantScopeThis},
			wantRoleVersionChange: 1,
			wantScopes:            []string{globals.GrantScopeThis},
			wantErr:               false,
		},
		{
			name: "project role add this grant scope then this is already set",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
			},
			inputAddScopes:        []string{globals.GrantScopeThis},
			wantReturnedScopes:    []string{},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeThis},
			wantErr:               false,
		},
		{
			name: "project role add children grant scope returns error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
			},
			inputAddScopes:        []string{globals.GrantScopeChildren},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeThis},
			wantErr:               true,
			wantErrMsg:            `iam.(Repository).AddRoleGrantScopes: iam.(projectRole).setGrantScope: hierarchical grant scope is not allowed for project role: parameter violation: error #100`,
		},
		{
			name: "project role add individual grant scope returns error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
			},
			inputAddScopes:        []string{proj2.PublicId},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeThis},
			wantErr:               true,
			wantErrMsg:            `iam.(Repository).AddRoleGrantScopes: individual role grant scope can only be set for global roles or org roles: parameter violation: error #100`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.setupRole(t)
			out, err := iamRepo.AddRoleGrantScopes(ctx, r.PublicId, r.Version, tc.inputAddScopes)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrMsg)
			} else {
				require.NoError(t, err)
				var outScopes []string
				for _, gs := range out {
					require.Equal(t, r.PublicId, gs.RoleId)
					outScopes = append(outScopes, gs.ScopeIdOrSpecial)
				}
				require.ElementsMatch(t, outScopes, tc.wantReturnedScopes)
			}
			// list the grant scopes again to verify that we're getting the expected grants scope
			afterRole, _, _, readbackGrantScopes, err := iamRepo.LookupRole(ctx, r.PublicId)
			require.NoError(t, err)
			var readbackScopeIds []string
			for _, gs := range readbackGrantScopes {
				require.Equal(t, r.PublicId, gs.RoleId)
				readbackScopeIds = append(readbackScopeIds, gs.ScopeIdOrSpecial)
			}
			require.ElementsMatch(t, readbackScopeIds, tc.wantScopes)
			require.Equal(t, r.Version+tc.wantRoleVersionChange, afterRole.Version)
		})
	}
}

func Test_SetRoleGrantScope(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := TestRepo(t, conn, wrap)
	org1, proj1 := TestScopes(t, iamRepo)
	org2, proj2 := TestScopes(t, iamRepo)

	testcases := []struct {
		name                    string
		setupRole               func(t *testing.T) *Role
		expectRemove            int
		expectRoleVersionChange uint32
		scopes                  []string // this is both the input and expect
		wantErr                 bool
		wantErrMsg              string
	}{
		{
			name: "global role sets this and children",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{"testing-none"}))
			},
			expectRemove:            0,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantErr:                 false,
		},
		{
			name: "global role sets this and children and individual project",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
			},
			expectRemove:            0,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj2.PublicId},
			wantErr:                 false,
		},
		{
			name: "global role sets all individual scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeDescendants}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			scopes:                  []string{org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId},
			wantErr:                 false,
		},
		{
			name: "global role set special and individual scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org1.PublicId, org2.PublicId}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId, proj2.PublicId},
			wantErr:                 false,
		},
		{
			name: "global role set different special and individual scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeDescendants}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeChildren, proj1.PublicId},
			wantErr:                 false,
		},
		{
			name: "global role change grants types from individual to children with individual scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, proj1.PublicId, proj2.PublicId}))
			},
			expectRemove:            0,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId, proj2.PublicId},
			wantErr:                 false,
		},
		{
			name: "global role set grants to mix type",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId}))
			},
			expectRemove:            4,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
			wantErr:                 false,
		},
		{
			name: "global role remove and add special",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis}))
			},
			expectRemove:            1,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeDescendants},
			wantErr:                 false,
		},
		{
			name: "global role set special conflicting scopes return error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix)
			},
			expectRemove:            0,
			expectRoleVersionChange: 0,
			scopes:                  []string{globals.GrantScopeChildren, globals.GrantScopeDescendants},
			wantErr:                 true,
			wantErrMsg:              "iam.(Repository).SetRoleGrantScopes: only one of ['children', 'descendants'] can be specified: parameter violation: error #100",
		},
		{
			name: "global role set individual conflicting scopes return error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix)
			},
			expectRemove:            0,
			expectRoleVersionChange: 0,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeDescendants, proj1.PublicId, proj2.PublicId},
			wantErr:                 true,
			wantErrMsg:              `iam.(Repository).SetRoleGrantScopes: db.DoTx: iam.(Repository).SetRoleGrantScopes: unable to add individual project grant scope for global role during set: db.CreateItems: insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_role_global_grant_scope_fkey": integrity violation: error #1003`,
		},
		{
			name: "global role set individual to remove individual grants",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			scopes:                  []string{org1.PublicId, proj1.PublicId},
			wantErr:                 false,
		},

		{
			name: "org role set no scopes to special",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{"testing-none"}))
			},
			expectRemove:            0,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantErr:                 false,
		},
		{
			name: "org role switch from specials to individual",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			scopes:                  []string{proj1.PublicId},
			wantErr:                 false,
		},
		{
			name: "org role set role to remove all special scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			scopes:                  []string{},
			wantErr:                 false,
		},
		{
			name: "org role set role to remove and add special",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeChildren}))
			},
			expectRemove:            1,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeThis},
			wantErr:                 false,
		},
		{
			name: "org role set role to remove all individual scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{proj1.PublicId}))
			},
			expectRemove:            1,
			expectRoleVersionChange: 1,
			scopes:                  []string{},
			wantErr:                 false,
		},
		{
			name: "org role add proj under another org returns error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, proj1.PublicId}))
			},
			expectRoleVersionChange: 0,
			scopes:                  []string{globals.GrantScopeThis, proj1.PublicId, proj2.PublicId},
			wantErr:                 true,
			wantErrMsg:              fmt.Sprintf("iam.(Repository).SetRoleGrantScopes: db.DoTx: iam.(Repository).SetRoleGrantScopes: unable to add individual project grant scope for org role during set: db.CreateItems: project scope_id %s not found in org: integrity violation: error #1104", proj2.PublicId),
		},
		{
			name: "org role conflicting grant scopes returns error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId)
			},
			expectRoleVersionChange: 0,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId},
			wantErr:                 true,
			wantErrMsg:              `iam.(Repository).SetRoleGrantScopes: db.DoTx: iam.(Repository).SetRoleGrantScopes: unable to add individual project grant scope for org role during set: db.CreateItems: insert or update on table "iam_role_org_individual_grant_scope" violates foreign key constraint "iam_role_org_grant_scope_fkey": integrity violation: error #1003`,
		},
		{
			name: "org role setting descendants grants returns error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId)
			},
			expectRoleVersionChange: 0,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
			wantErr:                 true,
			wantErrMsg:              `iam.(Repository).SetRoleGrantScopes: db.DoTx: iam.(Repository).SetRoleGrantScopes: unable to update role: db.Update: insert or update on table "iam_role_org" violates foreign key constraint "iam_role_org_grant_scope_enm_fkey": integrity violation: error #1003`,
		},
		{
			name: "project scope with 'this' grant sets empty scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
			},
			scopes:                  []string{},
			expectRoleVersionChange: 1,
			expectRemove:            1,
			wantErr:                 false,
		},
		{
			name: "project scope with 'this' grant",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{"testing-none"}))
			},
			scopes:                  []string{globals.GrantScopeThis},
			expectRoleVersionChange: 1,
			wantErr:                 false,
		},
		{
			name: "project setting special grants return error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{"testing-none"}))
			},
			scopes:                  []string{globals.GrantScopeChildren},
			expectRoleVersionChange: 0,
			wantErr:                 true,
			wantErrMsg:              `iam.(Repository).SetRoleGrantScopes: iam.(projectRole).setGrantScope: hierarchical grant scope is not allowed for project role: parameter violation: error #100`,
		},
		{
			name: "project setting individual grants return error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{"testing-none"}))
			},
			scopes:                  []string{proj2.PublicId},
			expectRoleVersionChange: 0,
			wantErr:                 true,
			wantErrMsg:              `iam.(Repository).SetRoleGrantScopes: roles in scope type project does not allow individual role grant scope: parameter violation: error #100`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.setupRole(t)
			got, removed, err := iamRepo.SetRoleGrantScopes(ctx, r.PublicId, r.Version, tc.scopes)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrMsg)
				afterRole, _, _, _, err := iamRepo.LookupRole(ctx, r.PublicId)
				require.NoError(t, err)
				require.Equal(t, r.Version, afterRole.Version)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectRemove, removed)
			var gotScopeIds []string
			for _, grantScope := range got {
				require.Equal(t, r.PublicId, grantScope.RoleId)
				gotScopeIds = append(gotScopeIds, grantScope.ScopeIdOrSpecial)
			}
			require.ElementsMatch(t, tc.scopes, gotScopeIds)

			// also validate using list
			afterRole, _, _, afterGrantScopes, err := iamRepo.LookupRole(ctx, r.PublicId)
			require.NoError(t, err)
			var listedScopeIds []string
			for _, grantScope := range afterGrantScopes {
				require.Equal(t, r.PublicId, grantScope.RoleId)
				listedScopeIds = append(listedScopeIds, grantScope.ScopeIdOrSpecial)
			}
			require.ElementsMatch(t, listedScopeIds, tc.scopes)
			require.Equal(t, r.Version+tc.expectRoleVersionChange, afterRole.Version)
		})
	}
}

func Test_DeleteRoleGrantScope(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := TestRepo(t, conn, wrap)
	org1, proj1 := TestScopes(t, iamRepo)
	org2, proj2 := TestScopes(t, iamRepo)

	testcases := []struct {
		name                    string
		setupRole               func(t *testing.T) *Role
		expectRemove            int
		expectRoleVersionChange uint32
		inputScopes             []string
		finalScopes             []string
		wantDeleted             int
		wantErr                 bool
		wantErrMsg              string
	}{
		{
			name: "global role delete this and descendants",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeDescendants}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			inputScopes:             []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
			finalScopes:             []string{},
			wantErr:                 false,
		},
		{
			name: "global role remove children with existing individually granted projects",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId, proj2.PublicId}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			inputScopes:             []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			finalScopes:             []string{proj1.PublicId, proj2.PublicId},
			wantErr:                 false,
		},
		{
			name: "global role remove individual scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId}))
			},
			expectRemove:            4,
			expectRoleVersionChange: 1,
			inputScopes:             []string{org1.PublicId, org2.PublicId, proj1.PublicId, proj2.PublicId},
			finalScopes:             []string{globals.GrantScopeThis},
			wantErr:                 false,
		},
		{
			name: "global role remove scopes that dont exist",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, org1.PublicId, org2.PublicId}))
			},
			expectRemove:            0,
			expectRoleVersionChange: 0,
			inputScopes:             []string{globals.GrantScopeChildren, proj1.PublicId, proj2.PublicId},
			finalScopes:             []string{globals.GrantScopeThis, org1.PublicId, org2.PublicId},
			wantErr:                 false,
		},
		{
			name: "org role remove special scopes",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			inputScopes:             []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			finalScopes:             []string{},
			wantErr:                 false,
		},
		{
			name: "org role remove individual scopes including scope that is not granted",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis, proj1.PublicId}))
			},
			expectRemove:            1,
			expectRoleVersionChange: 1,
			inputScopes:             []string{proj1.PublicId, proj2.PublicId},
			finalScopes:             []string{globals.GrantScopeThis},
			wantErr:                 false,
		},
		{
			name: "org role remove grants that don't exist",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, org2.PublicId, WithGrantScopeIds([]string{proj2.PublicId}))
			},
			expectRemove:            0,
			expectRoleVersionChange: 0,
			inputScopes:             []string{org1.PublicId, org2.PublicId},
			finalScopes:             []string{proj2.PublicId},
			wantErr:                 false,
		},
		{
			name: "project role remove this",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{globals.GrantScopeThis}))
			},
			inputScopes:             []string{globals.GrantScopeThis},
			wantErr:                 false,
			expectRemove:            1,
			expectRoleVersionChange: 1,
			finalScopes:             []string{},
		},
		{
			name: "project role remove this without this grant",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId, WithGrantScopeIds([]string{"testing-none"}))
			},
			inputScopes:             []string{globals.GrantScopeThis},
			wantErr:                 false,
			expectRemove:            0,
			expectRoleVersionChange: 0,
			finalScopes:             []string{},
		},
		{
			name: "project role remove this individual scope",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId)
			},
			inputScopes:             []string{proj2.PublicId},
			wantErr:                 false,
			expectRemove:            0,
			expectRoleVersionChange: 0,
			finalScopes:             []string{globals.GrantScopeThis},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.setupRole(t)
			removed, err := iamRepo.DeleteRoleGrantScopes(ctx, r.PublicId, r.Version, tc.inputScopes)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrMsg)
				afterRole, _, _, _, err := iamRepo.LookupRole(ctx, r.PublicId)
				require.NoError(t, err)
				require.Equal(t, r.Version, afterRole.Version)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectRemove, removed)
			afterRole, _, _, afterGrantScopes, err := iamRepo.LookupRole(ctx, r.PublicId)
			require.NoError(t, err)
			var afterGrantScopeIds []string
			for _, grantScope := range afterGrantScopes {
				require.Equal(t, r.PublicId, grantScope.RoleId)
				afterGrantScopeIds = append(afterGrantScopeIds, grantScope.ScopeIdOrSpecial)
			}
			require.ElementsMatch(t, tc.finalScopes, afterGrantScopeIds)
			require.Equal(t, r.Version+tc.expectRoleVersionChange, afterRole.Version)
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

// TestGrantsForUser_ACL_Allowed calls GrantsForUsers, parses the ACL, then calls `Allowed` to validate
// if the request is allowed (granted permission to take action)
func TestGrantsForUser_ACL_Allowed(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)

	repo := TestRepo(t, conn, wrap)
	user := TestUser(t, repo, "global")

	// Create a series of scopes with roles in each. We'll create two of each
	// kind to ensure we're not just picking up the first role in each.

	// The first org/project do not have any direct grants to the user. They
	// contain roles but the user is not a principal.
	noGrantOrg1, noGrantProj1 := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	noGrantOrg1Role := TestRole(t, conn, noGrantOrg1.PublicId)
	TestRoleGrant(t, conn, noGrantOrg1Role.PublicId, "ids=*;type=scope;actions=*")
	noGrantProj1Role := TestRole(t, conn, noGrantProj1.PublicId)
	TestRoleGrant(t, conn, noGrantProj1Role.PublicId, "ids=*;type=*;actions=*")
	noGrantOrg2, noGrantProj2 := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	noGrantOrg2Role := TestRole(t, conn, noGrantOrg2.PublicId)
	TestRoleGrant(t, conn, noGrantOrg2Role.PublicId, "ids=*;type=scope;actions=*")
	noGrantProj2Role := TestRole(t, conn, noGrantProj2.PublicId)
	TestRoleGrant(t, conn, noGrantProj2Role.PublicId, "ids=*;type=*;actions=*")

	// The second org/project set contains direct grants, but without
	// inheritance. We create two roles in each project.
	directGrantOrg1, directGrantProj1a := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	directGrantProj1b := TestProject(
		t,
		repo,
		directGrantOrg1.PublicId,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	directGrantOrg1Role := TestRole(t, conn, directGrantOrg1.PublicId)
	TestUserRole(t, conn, directGrantOrg1Role.PublicId, user.PublicId)
	directGrantOrg1RoleGrant1 := "ids=*;type=*;actions=*"
	TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant1)

	directGrantProj1aRole := TestRole(t, conn, directGrantProj1a.PublicId)
	TestUserRole(t, conn, directGrantProj1aRole.PublicId, user.PublicId)
	directGrantProj1aRoleGrant := "ids=*;type=target;actions=authorize-session,read"
	TestRoleGrant(t, conn, directGrantProj1aRole.PublicId, directGrantProj1aRoleGrant)
	directGrantProj1bRole := TestRole(t, conn, directGrantProj1b.PublicId)
	TestUserRole(t, conn, directGrantProj1bRole.PublicId, user.PublicId)
	directGrantProj1bRoleGrant := "ids=*;type=session;actions=list,read"
	TestRoleGrant(t, conn, directGrantProj1bRole.PublicId, directGrantProj1bRoleGrant)

	directGrantOrg2, directGrantProj2a := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	directGrantProj2b := TestProject(
		t,
		repo,
		directGrantOrg2.PublicId,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	directGrantOrg2Role := TestRole(t, conn, directGrantOrg2.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	TestUserRole(t, conn, directGrantOrg2Role.PublicId, user.PublicId)
	directGrantOrg2RoleGrant1 := "ids=*;type=user;actions=*"
	TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant1)
	directGrantOrg2RoleGrant2 := "ids=*;type=group;actions=list,read"
	TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant2)
	directGrantOrg2RoleGrant3 := "ids=*;type=credential-store;actions=*"
	TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant3)

	directGrantProj2aRole := TestRole(t, conn, directGrantProj2a.PublicId)
	TestUserRole(t, conn, directGrantProj2aRole.PublicId, user.PublicId)
	directGrantProj2aRoleGrant := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	TestRoleGrant(t, conn, directGrantProj2aRole.PublicId, directGrantProj2aRoleGrant)
	directGrantProj2bRole := TestRole(t, conn, directGrantProj2b.PublicId)
	TestUserRole(t, conn, directGrantProj2bRole.PublicId, user.PublicId)
	directGrantProj2bRoleGrant := "ids=cs_abcd1234;actions=read,update"
	TestRoleGrant(t, conn, directGrantProj2bRole.PublicId, directGrantProj2bRoleGrant)

	// For the third set we create a couple of orgs/projects and then use
	// globals.GrantScopeChildren.
	childGrantOrg1, childGrantOrg1Proj := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	childGrantOrg1Role := TestRole(t, conn, childGrantOrg1.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantOrg1Role.PublicId, user.PublicId)
	childGrantOrg1RoleGrant := "ids=*;type=host-set;actions=add-hosts,remove-hosts"
	TestRoleGrant(t, conn, childGrantOrg1Role.PublicId, childGrantOrg1RoleGrant)
	childGrantOrg2, childGrantOrg2Proj := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	childGrantOrg2Role := TestRole(t, conn, childGrantOrg2.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantOrg2Role.PublicId, user.PublicId)
	childGrantOrg2RoleGrant1 := "ids=*;type=session;actions=cancel:self"
	TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant1)
	childGrantOrg2RoleGrant2 := "ids=*;type=session;actions=read:self"
	TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant2)
	childGrantOrg3RoleGrant3 := "ids=*;type=group;actions=delete"
	TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg3RoleGrant3)

	// Finally, let's create some roles at global scope with children and
	// descendants grants
	childGrantGlobalRole := TestRole(t, conn, scope.Global.String(),
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantGlobalRole.PublicId, globals.AnyAuthenticatedUserId)
	childGrantGlobalRoleGrant := "ids=*;type=account;actions=*"
	TestRoleGrant(t, conn, childGrantGlobalRole.PublicId, childGrantGlobalRoleGrant)
	descendantGrantGlobalRole := TestRole(t, conn, scope.Global.String(),
		WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	TestUserRole(t, conn, descendantGrantGlobalRole.PublicId, globals.AnyAuthenticatedUserId)
	descendantGrantGlobalRoleGrant := "ids=*;type=group;actions=*"
	TestRoleGrant(t, conn, descendantGrantGlobalRole.PublicId, descendantGrantGlobalRoleGrant)

	type testCase struct {
		name       string
		res        perms.Resource
		act        action.Type
		shouldWork bool
	}
	testCases := []testCase{}

	// These test cases should fail because the grants are in roles where
	// the user is not a principal
	{
		testCases = append(testCases, testCase{
			name: "nogrant-a",
			res: perms.Resource{
				ScopeId:       noGrantOrg1.PublicId,
				Id:            "u_abcd1234",
				Type:          resource.Scope,
				ParentScopeId: scope.Global.String(),
			},
			act: action.Read,
		}, testCase{
			name: "nogrant-b",
			res: perms.Resource{
				ScopeId:       noGrantProj1.PublicId,
				Id:            "hsts_abcd1234",
				Type:          resource.HostSet,
				ParentScopeId: noGrantOrg1.String(),
			},
			act: action.Read,
		}, testCase{
			name: "nogrant-c",
			res: perms.Resource{
				ScopeId:       noGrantOrg2.PublicId,
				Id:            "u_abcd1234",
				Type:          resource.Scope,
				ParentScopeId: scope.Global.String(),
			},
			act: action.Read,
		}, testCase{
			name: "nogrant-d",
			res: perms.Resource{
				ScopeId:       noGrantProj2.PublicId,
				Id:            "r_abcd1234",
				Type:          resource.Role,
				ParentScopeId: noGrantOrg2.String(),
			},
			act: action.Read,
		},
		)
	}
	// These test cases are for org1 and its projects where the grants are
	// direct, not via children/descendants. They test some actions that
	// should work and some that shouldn't.
	{
		testCases = append(testCases, testCase{
			name: "direct-a",
			res: perms.Resource{
				ScopeId:       directGrantOrg1.PublicId,
				Id:            "u_abcd1234",
				Type:          resource.User,
				ParentScopeId: scope.Global.String(),
			},
			act:        action.Read,
			shouldWork: true,
		}, testCase{
			name: "direct-b",
			res: perms.Resource{
				ScopeId:       directGrantOrg1.PublicId,
				Id:            "r_abcd1234",
				Type:          resource.Role,
				ParentScopeId: scope.Global.String(),
			},
			act:        action.Read,
			shouldWork: true,
		}, testCase{
			name: "direct-c",
			res: perms.Resource{
				ScopeId:       directGrantProj1a.PublicId,
				Id:            "ttcp_abcd1234",
				Type:          resource.Target,
				ParentScopeId: directGrantOrg1.PublicId,
			},
			act:        action.AuthorizeSession,
			shouldWork: true,
		}, testCase{
			name: "direct-d",
			res: perms.Resource{
				ScopeId:       directGrantProj1a.PublicId,
				Id:            "s_abcd1234",
				Type:          resource.Session,
				ParentScopeId: directGrantOrg1.PublicId,
			},
			act: action.Read,
		}, testCase{
			name: "direct-e",
			res: perms.Resource{
				ScopeId:       directGrantProj1b.PublicId,
				Id:            "ttcp_abcd1234",
				Type:          resource.Target,
				ParentScopeId: directGrantOrg1.PublicId,
			},
			act: action.AuthorizeSession,
		}, testCase{
			name: "direct-f",
			res: perms.Resource{
				ScopeId:       directGrantProj1b.PublicId,
				Id:            "s_abcd1234",
				Type:          resource.Session,
				ParentScopeId: directGrantOrg1.PublicId,
			},
			act:        action.Read,
			shouldWork: true,
		},
		)
	}
	// These test cases are for org2 and its projects where the grants are
	// direct, not via children/descendants. They test some actions that
	// should work and some that shouldn't.
	{
		testCases = append(testCases, testCase{
			name: "direct-g",
			res: perms.Resource{
				ScopeId:       directGrantOrg2.PublicId,
				Id:            "u_abcd1234",
				Type:          resource.User,
				ParentScopeId: scope.Global.String(),
			},
			act:        action.Update,
			shouldWork: true,
		}, testCase{
			name: "direct-m",
			res: perms.Resource{
				ScopeId:       directGrantOrg2.PublicId,
				Id:            "at_abcd1234",
				Type:          resource.AuthToken,
				ParentScopeId: scope.Global.String(),
			},
			act: action.Update,
		}, testCase{
			name: "direct-h",
			res: perms.Resource{
				ScopeId:       directGrantOrg2.PublicId,
				Id:            "acct_abcd1234",
				Type:          resource.Account,
				ParentScopeId: scope.Global.String(),
			},
			act:        action.Delete,
			shouldWork: true,
		}, testCase{
			name: "direct-i",
			res: perms.Resource{
				ScopeId:       directGrantProj2a.PublicId,
				Type:          resource.Group,
				ParentScopeId: directGrantOrg2.PublicId,
			},
			act:        action.List,
			shouldWork: true,
		}, testCase{
			name: "direct-j",
			res: perms.Resource{
				ScopeId:       directGrantProj2a.PublicId,
				Id:            "r_abcd1234",
				Type:          resource.Role,
				ParentScopeId: directGrantOrg2.PublicId,
			},
			act: action.Read,
		}, testCase{
			name: "direct-n",
			res: perms.Resource{
				ScopeId:       directGrantProj2a.PublicId,
				Id:            "cs_abcd1234",
				Type:          resource.CredentialStore,
				ParentScopeId: directGrantOrg2.PublicId,
			},
			act:        action.Read,
			shouldWork: true,
		}, testCase{
			name: "direct-k",
			res: perms.Resource{
				ScopeId:       directGrantProj2a.PublicId,
				Id:            "hcst_abcd1234",
				Type:          resource.HostCatalog,
				ParentScopeId: directGrantOrg2.PublicId,
			},
			act:        action.Read,
			shouldWork: true,
		}, testCase{
			name: "direct-l",
			res: perms.Resource{
				ScopeId:       directGrantProj2b.PublicId,
				Id:            "cs_abcd1234",
				Type:          resource.CredentialStore,
				ParentScopeId: directGrantOrg2.PublicId,
			},
			act:        action.Update,
			shouldWork: true,
		},
			testCase{
				name: "direct-m",
				res: perms.Resource{
					ScopeId:       directGrantProj2b.PublicId,
					Id:            "cl_abcd1234",
					Type:          resource.CredentialLibrary,
					ParentScopeId: directGrantOrg2.PublicId,
				},
				act: action.Update,
			},
		)
	}
	// These test cases are child grants
	{
		testCases = append(testCases, testCase{
			name: "children-a",
			res: perms.Resource{
				ScopeId: scope.Global.String(),
				Id:      "a_abcd1234",
				Type:    resource.Account,
			},
			act: action.Update,
		}, testCase{
			name: "children-b",
			res: perms.Resource{
				ScopeId:       noGrantOrg1.PublicId,
				Id:            "a_abcd1234",
				Type:          resource.Account,
				ParentScopeId: scope.Global.String(),
			},
			act:        action.Update,
			shouldWork: true,
		}, testCase{
			name: "children-c",
			res: perms.Resource{
				ScopeId:       directGrantOrg1.PublicId,
				Id:            "a_abcd1234",
				Type:          resource.Account,
				ParentScopeId: scope.Global.String(),
			},
			act:        action.Update,
			shouldWork: true,
		}, testCase{
			name: "children-d",
			res: perms.Resource{
				ScopeId:       directGrantOrg2.PublicId,
				Id:            "a_abcd1234",
				Type:          resource.Account,
				ParentScopeId: scope.Global.String(),
			},
			act:        action.Update,
			shouldWork: true,
		}, testCase{
			name: "children-e",
			res: perms.Resource{
				ScopeId:       childGrantOrg2.PublicId,
				Id:            "oidc_abcd1234",
				Type:          resource.ManagedGroup,
				ParentScopeId: scope.Global.String(),
			},
			act: action.Delete,
		}, testCase{
			name: "children-f",
			res: perms.Resource{
				ScopeId:       childGrantOrg1Proj.PublicId,
				Id:            "s_abcd1234",
				Type:          resource.Session,
				ParentScopeId: childGrantOrg1.PublicId,
			},
			act: action.CancelSelf,
		}, testCase{
			name: "children-g",
			res: perms.Resource{
				ScopeId:       childGrantOrg2Proj.PublicId,
				Id:            "s_abcd1234",
				Type:          resource.Session,
				ParentScopeId: childGrantOrg2.PublicId,
			},
			act:        action.CancelSelf,
			shouldWork: true,
		}, testCase{
			name: "children-h",
			res: perms.Resource{
				ScopeId:       childGrantOrg2Proj.PublicId,
				Id:            "s_abcd1234",
				Type:          resource.Session,
				ParentScopeId: childGrantOrg2.PublicId,
			},
			act:        action.CancelSelf,
			shouldWork: true,
		}, testCase{
			name: "children-i",
			res: perms.Resource{
				ScopeId:       childGrantOrg1.PublicId,
				Id:            "sb_abcd1234",
				Type:          resource.StorageBucket,
				ParentScopeId: scope.Global.String(),
			},
			act: action.Update,
		}, testCase{
			name: "children-j",
			res: perms.Resource{
				ScopeId:       childGrantOrg1Proj.PublicId,
				Id:            "hsst_abcd1234",
				Type:          resource.HostSet,
				ParentScopeId: childGrantOrg1.PublicId,
			},
			act:        action.AddHosts,
			shouldWork: true,
		}, testCase{
			name: "children-k",
			res: perms.Resource{
				ScopeId:       childGrantOrg2Proj.PublicId,
				Id:            "hsst_abcd1234",
				Type:          resource.HostSet,
				ParentScopeId: childGrantOrg2.PublicId,
			},
			act: action.AddHosts,
		}, testCase{
			name: "children-l",
			res: perms.Resource{
				ScopeId:       childGrantOrg2Proj.PublicId,
				Id:            "hctg_abcd1234",
				Type:          resource.HostCatalog,
				ParentScopeId: childGrantOrg2.PublicId,
			},
			act: action.Update,
		},
		)
	}
	// These test cases are global descendants grants
	{
		testCases = append(testCases, testCase{
			name: "descendants-a",
			res: perms.Resource{
				ScopeId: scope.Global.String(),
				Id:      "g_abcd1234",
				Type:    resource.Group,
			},
			act: action.Update,
		}, testCase{
			name: "descendants-b",
			res: perms.Resource{
				ScopeId:       noGrantProj1.PublicId,
				Id:            "g_abcd1234",
				Type:          resource.Group,
				ParentScopeId: noGrantOrg1.PublicId,
			},
			act:        action.Update,
			shouldWork: true,
		}, testCase{
			name: "descendants-c",
			res: perms.Resource{
				ScopeId:       directGrantOrg2.PublicId,
				Id:            "g_abcd1234",
				Type:          resource.Group,
				ParentScopeId: scope.Global.String(),
			},
			act:        action.Update,
			shouldWork: true,
		}, testCase{
			name: "descendants-d",
			res: perms.Resource{
				ScopeId:       directGrantProj1a.PublicId,
				Id:            "g_abcd1234",
				Type:          resource.Group,
				ParentScopeId: directGrantOrg1.PublicId,
			},
			act:        action.Update,
			shouldWork: true,
		}, testCase{
			name: "descendants-e",
			res: perms.Resource{
				ScopeId:       directGrantProj1a.PublicId,
				Id:            "g_abcd1234",
				Type:          resource.Group,
				ParentScopeId: directGrantOrg1.PublicId,
			},
			act:        action.Update,
			shouldWork: true,
		}, testCase{
			name: "descendants-f",
			res: perms.Resource{
				ScopeId:       directGrantProj2b.PublicId,
				Id:            "g_abcd1234",
				Type:          resource.Group,
				ParentScopeId: directGrantOrg2.PublicId,
			},
			act:        action.Update,
			shouldWork: true,
		},
		)
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grantTuples, err := repo.GrantsForUser(ctx, user.PublicId, []resource.Type{tc.res.Type}, tc.res.ScopeId)
			require.NoError(t, err)
			grants := make([]perms.Grant, 0, len(grantTuples))
			for _, gt := range grantTuples {
				grant, err := perms.Parse(ctx, gt)
				require.NoError(t, err)
				grants = append(grants, grant)
			}
			acl := perms.NewACL(grants...)
			assert.True(t, acl.Allowed(tc.res, tc.act, "u_abc123").Authorized == tc.shouldWork)
		})
	}
}

// TestGrantsForUser_ACL_parsing calls GrantsForUsers then parse the result's ACL to validate that the
// returned map matches the expectation
func TestGrantsForUser_ACL_parsing(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)

	repo := TestRepo(t, conn, wrap)
	user := TestUser(t, repo, "global")

	// Create a series of scopes with roles in each. We'll create two of each
	// kind to ensure we're not just picking up the first role in each.

	// The first org/project do not have any direct grants to the user. They
	// contain roles but the user is not a principal.
	noGrantOrg1, noGrantProj1 := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	noGrantOrg1Role := TestRole(t, conn, noGrantOrg1.PublicId)
	TestRoleGrant(t, conn, noGrantOrg1Role.PublicId, "ids=*;type=scope;actions=*")
	noGrantProj1Role := TestRole(t, conn, noGrantProj1.PublicId)
	TestRoleGrant(t, conn, noGrantProj1Role.PublicId, "ids=*;type=*;actions=*")
	noGrantOrg2, noGrantProj2 := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	noGrantOrg2Role := TestRole(t, conn, noGrantOrg2.PublicId)
	TestRoleGrant(t, conn, noGrantOrg2Role.PublicId, "ids=*;type=scope;actions=*")
	noGrantProj2Role := TestRole(t, conn, noGrantProj2.PublicId)
	TestRoleGrant(t, conn, noGrantProj2Role.PublicId, "ids=*;type=*;actions=*")

	// The second org/project set contains direct grants, but without
	// inheritance. We create two roles in each project.
	directGrantOrg1, directGrantProj1a := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	directGrantProj1b := TestProject(
		t,
		repo,
		directGrantOrg1.PublicId,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	directGrantOrg1Role := TestRole(t, conn, directGrantOrg1.PublicId)
	TestUserRole(t, conn, directGrantOrg1Role.PublicId, user.PublicId)
	directGrantOrg1RoleGrant1 := "ids=*;type=*;actions=*"
	TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant1)
	directGrantOrg1RoleGrant2 := "ids=*;type=role;actions=list,read"
	TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant2)

	directGrantProj1aRole := TestRole(t, conn, directGrantProj1a.PublicId)
	TestUserRole(t, conn, directGrantProj1aRole.PublicId, user.PublicId)
	directGrantProj1aRoleGrant := "ids=*;type=target;actions=authorize-session,read"
	TestRoleGrant(t, conn, directGrantProj1aRole.PublicId, directGrantProj1aRoleGrant)
	directGrantProj1bRole := TestRole(t, conn, directGrantProj1b.PublicId)
	TestUserRole(t, conn, directGrantProj1bRole.PublicId, user.PublicId)
	directGrantProj1bRoleGrant := "ids=*;type=session;actions=list,read"
	TestRoleGrant(t, conn, directGrantProj1bRole.PublicId, directGrantProj1bRoleGrant)

	directGrantOrg2, directGrantProj2a := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	directGrantProj2b := TestProject(
		t,
		repo,
		directGrantOrg2.PublicId,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	directGrantOrg2Role := TestRole(t, conn, directGrantOrg2.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj2a.PublicId,
		}))
	TestUserRole(t, conn, directGrantOrg2Role.PublicId, user.PublicId)
	directGrantOrg2RoleGrant1 := "ids=*;type=user;actions=*"
	TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant1)
	directGrantOrg2RoleGrant2 := "ids=*;type=group;actions=list,read"
	TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant2)

	directGrantProj2aRole := TestRole(t, conn, directGrantProj2a.PublicId)
	TestUserRole(t, conn, directGrantProj2aRole.PublicId, user.PublicId)
	directGrantProj2aRoleGrant := "ids=hcst_abcd1234,hcst_1234abcd;actions=*"
	TestRoleGrant(t, conn, directGrantProj2aRole.PublicId, directGrantProj2aRoleGrant)
	directGrantProj2bRole := TestRole(t, conn, directGrantProj2b.PublicId)
	TestUserRole(t, conn, directGrantProj2bRole.PublicId, user.PublicId)
	directGrantProj2bRoleGrant := "ids=cs_abcd1234;actions=read,update"
	TestRoleGrant(t, conn, directGrantProj2bRole.PublicId, directGrantProj2bRoleGrant)

	// For the third set we create a couple of orgs/projects and then use
	// globals.GrantScopeChildren.
	childGrantOrg1, _ := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	childGrantOrg1Role := TestRole(t, conn, childGrantOrg1.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantOrg1Role.PublicId, user.PublicId)
	childGrantOrg1RoleGrant := "ids=*;type=host-set;actions=add-hosts,remove-hosts"
	TestRoleGrant(t, conn, childGrantOrg1Role.PublicId, childGrantOrg1RoleGrant)
	childGrantOrg2, _ := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	childGrantOrg2Role := TestRole(t, conn, childGrantOrg2.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantOrg2Role.PublicId, user.PublicId)
	childGrantOrg2RoleGrant1 := "ids=*;type=session;actions=cancel:self"
	TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant1)
	childGrantOrg2RoleGrant2 := "ids=*;type=session;actions=read:self"
	TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant2)

	// Finally, let's create some roles at global scope with children and
	// descendants grants
	childGrantGlobalRole := TestRole(t, conn, scope.Global.String(),
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantGlobalRole.PublicId, globals.AnyAuthenticatedUserId)
	childGrantGlobalRoleGrant := "ids=*;type=account;actions=*"
	TestRoleGrant(t, conn, childGrantGlobalRole.PublicId, childGrantGlobalRoleGrant)
	descendantGrantGlobalRole := TestRole(t, conn, scope.Global.String(),
		WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	TestUserRole(t, conn, descendantGrantGlobalRole.PublicId, globals.AnyAuthenticatedUserId)
	descendantGrantGlobalRoleGrant := "ids=*;type=credential;actions=*"
	TestRoleGrant(t, conn, descendantGrantGlobalRole.PublicId, descendantGrantGlobalRoleGrant)

	t.Run("acl-grants", func(t *testing.T) {
		// ACLs have to be calculated for each test because they care about different resources
		t.Run("descendant-grants", func(t *testing.T) {
			grantTuples, err := repo.GrantsForUser(ctx, user.PublicId, []resource.Type{resource.Credential}, globals.GlobalPrefix, WithRecursive(true))
			require.NoError(t, err)
			grants := make([]perms.Grant, 0, len(grantTuples))
			for _, gt := range grantTuples {
				grant, err := perms.Parse(ctx, gt)
				require.NoError(t, err)
				grants = append(grants, grant)
			}
			acl := perms.NewACL(grants...)

			descendantGrants := acl.DescendantsGrants()
			expDescendantGrants := []perms.AclGrant{
				{
					RoleScopeId:       scope.Global.String(),
					RoleParentScopeId: "",
					GrantScopeId:      globals.GrantScopeDescendants,
					Id:                "*",
					Type:              resource.Credential,
					ActionSet:         perms.ActionSet{action.All: true},
				},
			}
			assert.ElementsMatch(t, descendantGrants, expDescendantGrants)
		})

		t.Run("child-grants", func(t *testing.T) {
			grantTuples, err := repo.GrantsForUser(ctx, user.PublicId, []resource.Type{resource.Session}, globals.GlobalPrefix, WithRecursive(true))
			require.NoError(t, err)
			grants := make([]perms.Grant, 0, len(grantTuples))
			for _, gt := range grantTuples {
				grant, err := perms.Parse(ctx, gt)
				require.NoError(t, err)
				grants = append(grants, grant)
			}
			acl := perms.NewACL(grants...)

			childrenGrants := acl.ChildrenScopeGrantMap()
			expChildrenGrants := map[string][]perms.AclGrant{
				childGrantOrg2.PublicId: {
					{
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.Session,
						ActionSet:         perms.ActionSet{action.CancelSelf: true},
					},
					{
						RoleScopeId:       childGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.Session,
						ActionSet:         perms.ActionSet{action.ReadSelf: true},
					},
				},
			}
			assert.Len(t, childrenGrants, len(expChildrenGrants))
			for k, v := range childrenGrants {
				assert.ElementsMatch(t, v, expChildrenGrants[k])
			}
		})

		t.Run("direct-grants", func(t *testing.T) {
			grantTuples, err := repo.GrantsForUser(ctx, user.PublicId, []resource.Type{resource.Role}, globals.GlobalPrefix, WithRecursive(true))
			require.NoError(t, err)
			grants := make([]perms.Grant, 0, len(grantTuples))
			for _, gt := range grantTuples {
				grant, err := perms.Parse(ctx, gt)
				require.NoError(t, err)
				grants = append(grants, grant)
			}
			acl := perms.NewACL(grants...)

			directGrants := acl.DirectScopeGrantMap()
			expDirectGrants := map[string][]perms.AclGrant{
				directGrantOrg1.PublicId: {
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              resource.All,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg1.PublicId,
						Id:                "*",
						Type:              resource.Role,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantProj2a.PublicId: {
					{
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "hcst_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantProj2a.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "hcst_1234abcd",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.All: true},
					},
				},
				directGrantProj2b.PublicId: {
					{
						RoleScopeId:       directGrantProj2b.PublicId,
						RoleParentScopeId: directGrantOrg2.PublicId,
						GrantScopeId:      directGrantProj2b.PublicId,
						Id:                "cs_abcd1234",
						Type:              resource.Unknown,
						ActionSet:         perms.ActionSet{action.Update: true, action.Read: true},
					},
				},
			}
			assert.Len(t, directGrants, len(expDirectGrants))
			for k, v := range directGrants {
				assert.ElementsMatch(t, v, expDirectGrants[k])
			}
		})
	})
}
