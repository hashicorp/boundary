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

func Test_lookupRoleScope(t *testing.T) {
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
			name: "error adding mutually exclusive grants",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{"testing-none"}))
			},
			inputAddScopes:        []string{globals.GrantScopeChildren, globals.GrantScopeDescendants},
			wantRoleVersionChange: 0,
			wantScopes:            []string{},
			wantErr:               true,
		},
		{
			name: "org role add specials",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{"testing-none"}))
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
				return TestRole(t, conn, globals.GlobalPrefix)
			},
			inputAddScopes:        []string{proj1.PublicId, proj2.PublicId},
			wantReturnedScopes:    []string{proj1.PublicId, proj2.PublicId},
			wantRoleVersionChange: 1,
			wantScopes:            []string{globals.GrantScopeThis, proj1.PublicId, proj2.PublicId},
			wantErr:               false,
		},
		{
			name: "org role dedupe individual",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{proj1.PublicId, proj2.PublicId}))
			},
			inputAddScopes:        []string{proj1.PublicId, proj2.PublicId},
			wantReturnedScopes:    []string{},
			wantRoleVersionChange: 0,
			wantScopes:            []string{proj1.PublicId, proj2.PublicId},
			wantErr:               false,
		},
		{
			name: "org role dedupe special",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, globals.GrantScopeChildren}))
			},
			inputAddScopes:        []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantReturnedScopes:    []string{},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeThis, globals.GrantScopeChildren},
			wantErr:               false,
		},
		{
			name: "project role grant_scope cannot be added",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId)
			},
			inputAddScopes:        []string{globals.GrantScopeChildren},
			wantRoleVersionChange: 0,
			wantScopes:            []string{globals.GrantScopeThis},
			wantErr:               true,
			wantErrMsg:            `iam.(Repository).AddRoleGrantScopes: grant scope cannot be added to project role: parameter violation: error #100`,
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
			name: "global role change grants types from individual to children",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, globals.GlobalPrefix, WithGrantScopeIds([]string{globals.GrantScopeThis, proj1.PublicId, proj2.PublicId}))
			},
			expectRemove:            2,
			expectRoleVersionChange: 1,
			scopes:                  []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId, proj2.PublicId},
			wantErr:                 false,
		},
		{
			name: "project role returns error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId)
			},
			scopes:     []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId, proj2.PublicId},
			wantErr:    true,
			wantErrMsg: `iam.(Repository).SetRoleGrantScopes: grant scope cannot be added to project role: parameter violation: error #100`,
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
			require.ElementsMatch(t, gotScopeIds, tc.scopes)

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
			name: "global role remove special scopes",
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
			name: "org role remove individual scopes",
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
			name: "project role returns error",
			setupRole: func(t *testing.T) *Role {
				return TestRole(t, conn, proj1.PublicId)
			},
			inputScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren, proj1.PublicId, proj2.PublicId},
			wantErr:     true,
			wantErrMsg:  `iam.(Repository).DeleteRoleGrantScopes: grant scope cannot be deleted from a project role: parameter violation: error #100`,
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
