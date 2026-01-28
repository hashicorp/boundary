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
	"github.com/stretchr/testify/require"
)

func Test_globalRoleIndividualOrgGrantScope(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := TestRepo(t, conn, wrap)
	rw := db.New(conn)
	org, proj := TestScopes(t, iamRepo)
	testcases := []struct {
		name       string
		setup      func(t *testing.T) *globalRoleIndividualOrgGrantScope
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "happy path grant scope individual",
			setup: func(t *testing.T) *globalRoleIndividualOrgGrantScope {
				r := TestRole(t, conn, globals.GlobalPrefix)
				return &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "error only individual is allowed in grant_scope",
			setup: func(t *testing.T) *globalRoleIndividualOrgGrantScope {
				r := TestRole(t, conn, globals.GlobalPrefix)
				gRole := allocGlobalRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))

				gRole.GrantScope = globals.GrantScopeChildren
				updated, err := rw.Update(ctx, &gRole, []string{"GrantScope"}, []string{})
				require.NoError(t, err)
				require.Equal(t, 1, updated)
				return &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org.PublicId,
						GrantScope: globals.GrantScopeChildren,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: only_individual_grant_scope_allowed constraint failed: check constraint violated: integrity violation: error #1000`,
		},
		{
			name: "error mismatch grant_scope",
			setup: func(t *testing.T) *globalRoleIndividualOrgGrantScope {
				r := TestRole(t, conn, globals.GlobalPrefix)
				gRole := allocGlobalRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))
				return &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org.PublicId,
						GrantScope: globals.GrantScopeChildren,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: only_individual_grant_scope_allowed constraint failed: check constraint violated: integrity violation: error #1000`,
		},
		{
			name: "error trying to add project grant scope",
			setup: func(t *testing.T) *globalRoleIndividualOrgGrantScope {
				r := TestRole(t, conn, globals.GlobalPrefix)
				return &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_scope_org_fkey": integrity violation: error #1003`,
		},
		{
			name: "error cannot add GlobalRoleIndividualOrgGrantScope for org role",
			setup: func(t *testing.T) *globalRoleIndividualOrgGrantScope {
				r := TestRole(t, conn, org.PublicId)
				return &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_role_global_fkey": integrity violation: error #1003`,
		},
		{
			name: "error cannot add GlobalRoleIndividualOrgGrantScope for proj role",
			setup: func(t *testing.T) *globalRoleIndividualOrgGrantScope {
				r := TestRole(t, conn, proj.PublicId)
				return &globalRoleIndividualOrgGrantScope{
					GlobalRoleIndividualOrgGrantScope: &store.GlobalRoleIndividualOrgGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global_individual_org_grant_scope" violates foreign key constraint "iam_role_global_fkey": integrity violation: error #1003`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			grantScope := tc.setup(t)
			err := rw.Create(ctx, grantScope)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}

func Test_GlobalRoleIndividualProjectGrantScope(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := TestRepo(t, conn, wrap)
	rw := db.New(conn)
	org, proj := TestScopes(t, iamRepo)
	testcases := []struct {
		name       string
		setup      func(t *testing.T) *globalRoleIndividualProjectGrantScope
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "happy path grant scope individual",
			setup: func(t *testing.T) *globalRoleIndividualProjectGrantScope {
				r := TestRole(t, conn, globals.GlobalPrefix)
				return &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "happy path grant_scope children is allowed",
			setup: func(t *testing.T) *globalRoleIndividualProjectGrantScope {
				r := TestRole(t, conn, globals.GlobalPrefix)
				gRole := allocGlobalRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))

				gRole.GrantScope = globals.GrantScopeChildren
				updated, err := rw.Update(ctx, &gRole, []string{"GrantScope"}, []string{})
				require.NoError(t, err)
				require.Equal(t, 1, updated)
				return &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeChildren,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "error mismatch grant_scope",
			setup: func(t *testing.T) *globalRoleIndividualProjectGrantScope {
				r := TestRole(t, conn, globals.GlobalPrefix)
				return &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeChildren,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_role_global_grant_scope_fkey": integrity violation: error #1003`,
		},
		{
			name: "error trying to add org grant scope",
			setup: func(t *testing.T) *globalRoleIndividualProjectGrantScope {
				r := TestRole(t, conn, globals.GlobalPrefix)
				return &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_scope_project_fkey": integrity violation: error #1003`,
		},
		{
			name: "error cannot add GlobalRoleIndividualProjectGrantScope for org role",
			setup: func(t *testing.T) *globalRoleIndividualProjectGrantScope {
				r := TestRole(t, conn, org.PublicId)
				return &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_role_global_fkey": integrity violation: error #1003`,
		},
		{
			name: "error cannot add GlobalRoleIndividualProjectGrantScope for proj role",
			setup: func(t *testing.T) *globalRoleIndividualProjectGrantScope {
				r := TestRole(t, conn, proj.PublicId)
				return &globalRoleIndividualProjectGrantScope{
					GlobalRoleIndividualProjectGrantScope: &store.GlobalRoleIndividualProjectGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_global_individual_project_grant_scope" violates foreign key constraint "iam_role_global_fkey": integrity violation: error #1003`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			grantScope := tc.setup(t)
			err := rw.Create(ctx, grantScope)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}

func Test_OrgRoleIndividualGrantScope(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := TestRepo(t, conn, wrap)
	rw := db.New(conn)
	org, proj := TestScopes(t, iamRepo)
	_, proj2 := TestScopes(t, iamRepo)
	testcases := []struct {
		name       string
		setup      func(t *testing.T) *orgRoleIndividualGrantScope
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "happy path grant scope individual",
			setup: func(t *testing.T) *orgRoleIndividualGrantScope {
				r := TestRole(t, conn, org.PublicId)
				return &orgRoleIndividualGrantScope{
					OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr: false,
		},
		{
			name: "error only individual is allowed in grant_scope",
			setup: func(t *testing.T) *orgRoleIndividualGrantScope {
				r := TestRole(t, conn, org.PublicId)
				gRole := allocOrgRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))

				gRole.GrantScope = globals.GrantScopeChildren
				updated, err := rw.Update(ctx, &gRole, []string{"GrantScope"}, []string{})
				require.NoError(t, err)
				require.Equal(t, 1, updated)
				return &orgRoleIndividualGrantScope{
					OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeChildren,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: "db.Create: only_individual_grant_scope_allowed constraint failed: check constraint violated: integrity violation: error #1000",
		},
		{
			name: "error only iam_role_org.grant_scope individual is allowed in grant_scope",
			setup: func(t *testing.T) *orgRoleIndividualGrantScope {
				r := TestRole(t, conn, org.PublicId)
				gRole := allocOrgRole()
				gRole.PublicId = r.PublicId
				require.NoError(t, rw.LookupByPublicId(ctx, &gRole))

				gRole.GrantScope = globals.GrantScopeChildren
				updated, err := rw.Update(ctx, &gRole, []string{"GrantScope"}, []string{})
				require.NoError(t, err)
				require.Equal(t, 1, updated)
				return &orgRoleIndividualGrantScope{
					OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: insert or update on table "iam_role_org_individual_grant_scope" violates foreign key constraint "iam_role_org_grant_scope_fkey": integrity violation: error #1003`,
		},
		{
			name: "error mismatch grant_scope",
			setup: func(t *testing.T) *orgRoleIndividualGrantScope {
				r := TestRole(t, conn, org.PublicId)
				return &orgRoleIndividualGrantScope{
					OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj.PublicId,
						GrantScope: globals.GrantScopeChildren,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: `db.Create: only_individual_grant_scope_allowed constraint failed: check constraint violated: integrity violation: error #1000`,
		},
		{
			name: "error trying to add org scope to grant_scope",
			setup: func(t *testing.T) *orgRoleIndividualGrantScope {
				r := TestRole(t, conn, org.PublicId)
				return &orgRoleIndividualGrantScope{
					OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: fmt.Sprintf("db.Create: project scope_id %s not found in org: integrity violation: error #1104", org.PublicId),
		},
		{
			name: "error cannot add proj not belong to org",
			setup: func(t *testing.T) *orgRoleIndividualGrantScope {
				r := TestRole(t, conn, org.PublicId)
				return &orgRoleIndividualGrantScope{
					OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    org.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: fmt.Sprintf("db.Create: project scope_id %s not found in org: integrity violation: error #1104", org.PublicId),
		},
		{
			name: "error cannot add proj not belong to org",
			setup: func(t *testing.T) *orgRoleIndividualGrantScope {
				r := TestRole(t, conn, org.PublicId)
				return &orgRoleIndividualGrantScope{
					OrgRoleIndividualGrantScope: &store.OrgRoleIndividualGrantScope{
						RoleId:     r.PublicId,
						ScopeId:    proj2.PublicId,
						GrantScope: globals.GrantScopeIndividual,
					},
				}
			},
			wantErr:    true,
			wantErrMsg: fmt.Sprintf("db.Create: project scope_id %s not found in org: integrity violation: error #1104", proj2.PublicId),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			grantScope := tc.setup(t)
			err := rw.Create(ctx, grantScope)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}
