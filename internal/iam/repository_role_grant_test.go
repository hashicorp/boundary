// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddRoleGrants(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	_, proj := TestScopes(t, repo)
	role := TestRole(t, conn, proj.PublicId)
	createGrantsFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			g := fmt.Sprintf("ids=hc_%d;actions=*", i)
			results = append(results, g)
		}
		return results
	}
	type args struct {
		roleId      string
		roleVersion uint32
		grants      []string
		opt         []Option
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "valid",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1,
				grants:      createGrantsFn(),
			},
			wantErr: false,
		},
		{
			name: "no-grants",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 2,
				grants:      nil,
			},
			wantErr: true,
		},
		{
			name: "bad-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1000,
				grants:      createGrantsFn(),
			},
			wantErr: true,
		},
		{
			name: "zero-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 0,
				grants:      createGrantsFn(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { rg := allocRoleGrant(); return &rg }(), "1=1")
			got, err := repo.AddRoleGrants(context.Background(), tt.args.roleId, tt.args.roleVersion, tt.args.grants, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			gotRoleGrant := map[string]*RoleGrant{}
			for _, r := range got {
				gotRoleGrant[r.CanonicalGrant] = r
			}

			err = db.TestVerifyOplog(t, rw, role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			foundRoleGrants, err := repo.ListRoleGrants(context.Background(), role.PublicId)
			require.NoError(err)
			// Create a map of grants to check against
			grantSet := make(map[string]bool, len(tt.args.grants))
			for _, grant := range tt.args.grants {
				grantSet[grant] = true
			}
			for _, r := range foundRoleGrants {
				roleGrant := gotRoleGrant[r.CanonicalGrant]
				assert.NotEmpty(roleGrant)
				assert.Equal(roleGrant.GetRoleId(), r.GetRoleId())
				assert.NotEmpty(grantSet[roleGrant.CanonicalGrant])
				delete(grantSet, roleGrant.CanonicalGrant)
			}
			assert.Empty(grantSet)
		})
	}
}

func TestRepository_ListRoleGrants(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper, WithLimit(testLimit))
	org, proj := TestScopes(t, repo)

	type args struct {
		withRoleId string
		opt        []Option
	}
	tests := []struct {
		name          string
		createCnt     int
		createScopeId string
		args          args
		wantCnt       int
		wantErr       bool
	}{
		{
			name:          "no-limit",
			createCnt:     repo.defaultLimit + 2,
			createScopeId: org.PublicId,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 2,
			wantErr: false,
		},
		{
			name:          "no-limit-proj-group",
			createCnt:     repo.defaultLimit + 2,
			createScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 2,
			wantErr: false,
		},
		{
			name:          "default-limit",
			createCnt:     repo.defaultLimit + 2,
			createScopeId: org.PublicId,
			wantCnt:       repo.defaultLimit,
			wantErr:       false,
		},
		{
			name:          "custom-limit",
			createCnt:     repo.defaultLimit + 2,
			createScopeId: org.PublicId,
			args: args{
				opt: []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:          "bad-role-id",
			createCnt:     2,
			createScopeId: org.PublicId,
			args: args{
				withRoleId: "bad-id",
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { r := allocRole(); return &r }(), "1=1")
			role := TestRole(t, conn, tt.createScopeId)
			roleGrants := make([]string, 0, tt.createCnt)
			for i := 0; i < tt.createCnt; i++ {
				roleGrants = append(roleGrants, fmt.Sprintf("ids=h_%d;actions=*", i))
			}
			testRoles, err := repo.AddRoleGrants(context.Background(), role.PublicId, role.Version, roleGrants, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.createCnt, len(testRoles))

			var roleId string
			switch {
			case tt.args.withRoleId != "":
				roleId = tt.args.withRoleId
			default:
				roleId = role.PublicId
			}
			got, err := repo.ListRoleGrants(context.Background(), roleId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func TestRepository_DeleteRoleGrants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	type args struct {
		role                 *Role
		roleIdOverride       *string
		roleVersionOverride  *uint32
		grantStringsOverride []string
		createCnt            int
		deleteCnt            int
		opt                  []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsErr       errors.Code
	}{
		{
			name: "valid",
			args: args{
				role:      TestRole(t, conn, org.PublicId),
				createCnt: 5,
				deleteCnt: 5,
			},
			wantRowsDeleted: 5,
			wantErr:         false,
		},
		{
			name: "valid-keeping-some",
			args: args{
				role:      TestRole(t, conn, org.PublicId),
				createCnt: 5,
				deleteCnt: 3,
			},
			wantRowsDeleted: 3,
			wantErr:         false,
		},

		{
			name: "no-deletes",
			args: args{
				role:      TestRole(t, conn, org.PublicId),
				createCnt: 5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},

		{
			name: "not-found",
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				roleIdOverride: func() *string { id := testId(t); return &id }(),
				createCnt:      5,
				deleteCnt:      5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "missing-role-id",
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				roleIdOverride: func() *string { id := ""; return &id }(),
				createCnt:      5,
				deleteCnt:      5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "invalid-grant-strings",
			args: args{
				role:                 TestRole(t, conn, org.PublicId),
				grantStringsOverride: []string{"ids=s_87;actions=*"},
				createCnt:            5,
				deleteCnt:            3,
			},
			wantRowsDeleted: 2,
		},
		{
			name: "zero-version",
			args: args{
				role:                TestRole(t, conn, org.PublicId),
				createCnt:           5,
				deleteCnt:           5,
				roleVersionOverride: func() *uint32 { v := uint32(0); return &v }(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
		{
			name: "bad-version",
			args: args{
				role:                TestRole(t, conn, org.PublicId),
				createCnt:           5,
				deleteCnt:           5,
				roleVersionOverride: func() *uint32 { v := uint32(1000); return &v }(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { rg := allocRoleGrant(); return &rg }(), "1=1")
			grants := make([]*RoleGrant, 0, tt.args.createCnt)
			grantStrings := make([]string, 0, tt.args.createCnt)
			for i := 0; i < tt.args.createCnt; i++ {
				g, err := NewRoleGrant(ctx, tt.args.role.PublicId, fmt.Sprintf("actions=*;ids=s_%d", i), tt.args.opt...)
				require.NoError(err)
				grantStrings = append(grantStrings, g.RawGrant)
				grants = append(grants, g)
			}
			roleGrants, err := repo.AddRoleGrants(context.Background(), tt.args.role.PublicId, 1, grantStrings, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.args.createCnt, len(roleGrants))

			deleteCanonicalGrants := make([]string, 0, tt.args.deleteCnt)
			deleteGrants := make([]string, 0, tt.args.deleteCnt)
			for i := 0; i < tt.args.deleteCnt; i++ {
				deleteCanonicalGrants = append(deleteCanonicalGrants, grants[i].CanonicalGrant)
				deleteGrants = append(deleteGrants, fmt.Sprintf("ids=s_%d;actions=*", i))
			}
			for i, override := range tt.args.grantStringsOverride {
				deleteCanonicalGrants = deleteCanonicalGrants[1:]
				deleteGrants[i] = override
			}

			var roleId string
			switch {
			case tt.args.roleIdOverride != nil:
				roleId = *tt.args.roleIdOverride
			default:
				roleId = tt.args.role.PublicId
			}
			var roleVersion uint32
			switch {
			case tt.args.roleVersionOverride != nil:
				roleVersion = *tt.args.roleVersionOverride
			default:
				roleVersion = 2
			}
			deletedRows, err := repo.DeleteRoleGrants(context.Background(), roleId, roleVersion, deleteGrants, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "unexpected error %s", err.Error())
				err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			roleGrants = []*RoleGrant{}
			require.NoError(repo.reader.SearchWhere(context.Background(), &roleGrants, "role_id = ?", []any{roleId}))
			found := map[string]bool{}
			for _, rg := range roleGrants {
				found[rg.CanonicalGrant] = true
			}
			for _, i := range deleteCanonicalGrants {
				assert.False(found[i])
			}

			err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_SetRoleGrants_Randomize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	role := TestRole(t, conn, org.PublicId)
	db.TestDeleteWhere(t, conn, func() any { i := allocRoleGrant(); return &i }(), "1=1")

	type roleGrantWrapper struct {
		grantString string
		enabled     bool
	}

	totalCnt := 30
	grants := make([]*roleGrantWrapper, 0, totalCnt)
	for i := 0; i < totalCnt; i++ {
		g, err := NewRoleGrant(ctx, role.PublicId, fmt.Sprintf("ids=s_%d;actions=*", i))
		require.NoError(err)
		grants = append(grants, &roleGrantWrapper{
			grantString: g.RawGrant,
		})
	}

	// Each loop will set some number of role grants to enabled or disabled
	// randomly and then validate after setting that what's set matches
	var grantsToSet []string
	var expected map[string]bool
	for i := 1; i <= totalCnt; i++ {
		grantsToSet = make([]string, 0, totalCnt)
		expected = make(map[string]bool, totalCnt)
		rand.Seed(time.Now().UnixNano())
		for _, rgw := range grants {
			rgw.enabled = rand.Int()%2 == 0
			if rgw.enabled {
				grantsToSet = append(grantsToSet, rgw.grantString)
				expected[rgw.grantString] = true
			}
		}

		// First time, run a couple of error conditions
		if i == 1 {
			_, _, err := repo.SetRoleGrants(ctx, "", 1, []string{})
			require.Error(err)
			_, _, err = repo.SetRoleGrants(ctx, role.PublicId, 1, nil)
			require.Error(err)
		}

		_, _, err := repo.SetRoleGrants(ctx, role.PublicId, uint32(i), grantsToSet)
		require.NoError(err)

		roleGrants, err := repo.ListRoleGrants(ctx, role.PublicId)
		require.NoError(err)
		require.Equal(len(grantsToSet), len(roleGrants))
		for _, rg := range roleGrants {
			require.Contains(expected, rg.CanonicalGrant)
			delete(expected, rg.CanonicalGrant)
		}
		require.Empty(expected)
	}

	// At the end, set to explicitly empty and make sure all are cleared out
	_, _, err := repo.SetRoleGrants(context.Background(), role.PublicId, uint32(totalCnt+1), []string{})
	require.NoError(err)

	roleGrants, err := repo.ListRoleGrants(context.Background(), role.PublicId)
	require.NoError(err)
	require.Empty(roleGrants)
}

func TestRepository_SetRoleGrants_Parameters(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	role := TestRole(t, conn, org.PublicId)
	type args struct {
		roleId      string
		roleVersion uint32
		grants      []string
		opt         []Option
	}
	tests := []struct {
		name             string
		args             args
		want             []*RoleGrant
		wantAffectedRows int
		wantErr          bool
	}{
		{
			name: "missing-roleid",
			args: args{
				roleId:      "",
				roleVersion: 1,
				grants:      []string{"ids=s_1;actions=*"},
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
		{
			name: "bad-roleid",
			args: args{
				roleId:      "bad-roleid",
				roleVersion: 1,
				grants:      []string{"ids=s_1;actions=*"},
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
		{
			name: "nil-grants",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1,
				grants:      nil,
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
		{
			name: "zero-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 0,
				grants:      []string{"ids=s_1;actions=*"},
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
		{
			name: "bad-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1000,
				grants:      []string{"ids=s_1;actions=*"},
			},
			want:             nil,
			wantAffectedRows: 0,
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rg := allocRoleGrant()
			db.TestDeleteWhere(t, conn, &rg, "1=1")
			got, gotAffectedRows, err := repo.SetRoleGrants(context.Background(), tt.args.roleId, tt.args.roleVersion, tt.args.grants, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
			} else {
				require.NoError(err)
			}
			assert.Equal(tt.wantAffectedRows, gotAffectedRows)
			assert.Equal(tt.want, got)
		})
	}
}

func TestGrantsForUser(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
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
	TestRoleGrant(t, conn, noGrantOrg1Role.PublicId, "id=o_noGrantOrg1;actions=*")
	noGrantProj1Role := TestRole(t, conn, noGrantProj1.PublicId)
	TestRoleGrant(t, conn, noGrantProj1Role.PublicId, "id=p_noGrantProj1;actions=*")
	noGrantOrg2, noGrantProj2 := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	noGrantOrg2Role := TestRole(t, conn, noGrantOrg2.PublicId)
	TestRoleGrant(t, conn, noGrantOrg2Role.PublicId, "id=o_noGrantOrg2;actions=*")
	noGrantProj2Role := TestRole(t, conn, noGrantProj2.PublicId)
	TestRoleGrant(t, conn, noGrantProj2Role.PublicId, "id=p_noGrantProj2;actions=*")

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
	directGrantOrg1Role := TestRole(t, conn, directGrantOrg1.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeThis,
			directGrantProj1a.PublicId,
			directGrantProj1b.PublicId,
		}))
	TestUserRole(t, conn, directGrantOrg1Role.PublicId, user.PublicId)
	directGrantOrg1RoleGrant := "id=o_directGrantOrg1;actions=*"
	TestRoleGrant(t, conn, directGrantOrg1Role.PublicId, directGrantOrg1RoleGrant)
	directGrantProj1aRole := TestRole(t, conn, directGrantProj1a.PublicId)
	TestUserRole(t, conn, directGrantProj1aRole.PublicId, user.PublicId)
	directGrantProj1aRoleGrant := "id=p_directGrantProj1a;actions=*"
	TestRoleGrant(t, conn, directGrantProj1aRole.PublicId, directGrantProj1aRoleGrant)
	directGrantProj1bRole := TestRole(t, conn, directGrantProj1b.PublicId)
	TestUserRole(t, conn, directGrantProj1bRole.PublicId, user.PublicId)
	directGrantProj1bRoleGrant := "id=p_directGrantProj1b;actions=*"
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
			directGrantProj2b.PublicId,
		}))
	TestUserRole(t, conn, directGrantOrg2Role.PublicId, user.PublicId)
	directGrantOrg2RoleGrant := "id=o_directGrantOrg2;actions=*"
	TestRoleGrant(t, conn, directGrantOrg2Role.PublicId, directGrantOrg2RoleGrant)
	directGrantProj2aRole := TestRole(t, conn, directGrantProj2a.PublicId)
	TestUserRole(t, conn, directGrantProj2aRole.PublicId, user.PublicId)
	directGrantProj2aRoleGrant := "id=p_directGrantProj2a;actions=*"
	TestRoleGrant(t, conn, directGrantProj2aRole.PublicId, directGrantProj2aRoleGrant)
	directGrantProj2bRole := TestRole(t, conn, directGrantProj2b.PublicId)
	TestUserRole(t, conn, directGrantProj2bRole.PublicId, user.PublicId)
	directGrantProj2bRoleGrant := "id=p_directGrantProj2b;actions=*"
	TestRoleGrant(t, conn, directGrantProj2bRole.PublicId, directGrantProj2bRoleGrant)

	// For the third set we create a couple of orgs/projects and then use
	// "children". We expect to see no grant on the org but for both projects.
	childGrantOrg1, childGrantProj1a := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	childGrantProj1b := TestProject(
		t,
		repo,
		childGrantOrg1.PublicId,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	childGrantOrg1Role := TestRole(t, conn, childGrantOrg1.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantOrg1Role.PublicId, user.PublicId)
	childGrantOrg1RoleGrant := "id=o_childGrantOrg1;actions=*"
	TestRoleGrant(t, conn, childGrantOrg1Role.PublicId, childGrantOrg1RoleGrant)
	childGrantOrg2, childGrantProj2a := TestScopes(
		t,
		repo,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	childGrantProj2b := TestProject(
		t,
		repo,
		childGrantOrg2.PublicId,
		WithSkipAdminRoleCreation(true),
		WithSkipDefaultRoleCreation(true),
	)
	childGrantOrg2Role := TestRole(t, conn, childGrantOrg2.PublicId,
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantOrg2Role.PublicId, user.PublicId)
	childGrantOrg2RoleGrant := "id=o_childGrantOrg2;actions=*"
	TestRoleGrant(t, conn, childGrantOrg2Role.PublicId, childGrantOrg2RoleGrant)

	// Finally, let's create some roles at global scope with children and
	// descendants grants
	childGrantGlobalRole := TestRole(t, conn, scope.Global.String(),
		WithGrantScopeIds([]string{
			globals.GrantScopeChildren,
		}))
	TestUserRole(t, conn, childGrantGlobalRole.PublicId, globals.AnyAuthenticatedUserId)
	childGrantGlobalRoleGrant := "id=*;type=host;actions=*"
	TestRoleGrant(t, conn, childGrantGlobalRole.PublicId, childGrantGlobalRoleGrant)
	descendantGrantGlobalRole := TestRole(t, conn, scope.Global.String(),
		WithGrantScopeIds([]string{
			globals.GrantScopeDescendants,
		}))
	TestUserRole(t, conn, descendantGrantGlobalRole.PublicId, globals.AnyAuthenticatedUserId)
	descendantGrantGlobalRoleGrant := "id=*;type=credential;actions=*"
	TestRoleGrant(t, conn, descendantGrantGlobalRole.PublicId, descendantGrantGlobalRoleGrant)

	/*
		// Useful if needing to debug
		t.Log(
			"\nnoGrantOrg1", noGrantOrg1.PublicId, noGrantOrg1Role.PublicId,
			"\nnoGrantProj1", noGrantProj1.PublicId, noGrantProj1Role.PublicId,
			"\nnoGrantOrg2", noGrantOrg2.PublicId, noGrantOrg2Role.PublicId,
			"\nnoGrantProj2", noGrantProj2.PublicId, noGrantProj2Role.PublicId,
			"\ndirectGrantOrg1", directGrantOrg1.PublicId, directGrantOrg1Role.PublicId,
			"\ndirectGrantProj1a", directGrantProj1a.PublicId, directGrantProj1aRole.PublicId,
			"\ndirectGrantProj1b", directGrantProj1b.PublicId, directGrantProj1bRole.PublicId,
			"\ndirectGrantOrg2", directGrantOrg2.PublicId, directGrantOrg2Role.PublicId,
			"\ndirectGrantProj2a", directGrantProj2a.PublicId, directGrantProj2aRole.PublicId,
			"\ndirectGrantProj2b", directGrantProj2b.PublicId, directGrantProj2bRole.PublicId,
			"\nchildGrantOrg1", childGrantOrg1.PublicId, childGrantOrg1Role.PublicId,
			"\nchildGrantProj1a", childGrantProj1a.PublicId,
			"\nchildGrantProj1b", childGrantProj1b.PublicId,
			"\nchildGrantOrg2", childGrantOrg2.PublicId, childGrantOrg2Role.PublicId,
			"\nchildGrantProj2a", childGrantProj2a.PublicId,
			"\nchildGrantProj2b", childGrantProj2b.PublicId,
			"\nchildGrantGlobalRole", childGrantGlobalRole.PublicId,
			"\ndescendantGrantGlobalRole", descendantGrantGlobalRole.PublicId,
		)
	*/

	// We expect to see:
	//
	// * No grants from noOrg/noProj
	// * Grants from direct orgs/projs:
	//   * directGrantOrg1/directGrantOrg2 on org and respective projects (6 grants total)
	//   * directGrantProj on respective projects (4 grants total)
	expGrantTuples := []perms.GrantTuple{
		// No grants from noOrg/noProj

		// Grants from direct org1 to org1/proj1a/proj1b:
		{
			RoleId:  directGrantOrg1Role.PublicId,
			ScopeId: directGrantOrg1.PublicId,
			Grant:   directGrantOrg1RoleGrant,
		},
		{
			RoleId:  directGrantOrg1Role.PublicId,
			ScopeId: directGrantProj1a.PublicId,
			Grant:   directGrantOrg1RoleGrant,
		},
		{
			RoleId:  directGrantOrg1Role.PublicId,
			ScopeId: directGrantProj1b.PublicId,
			Grant:   directGrantOrg1RoleGrant,
		},
		// Grants from direct org 1 proj 1a:
		{
			RoleId:  directGrantProj1aRole.PublicId,
			ScopeId: directGrantProj1a.PublicId,
			Grant:   directGrantProj1aRoleGrant,
		},
		// Grant from direct org 1 proj 1 b:
		{
			RoleId:  directGrantProj1bRole.PublicId,
			ScopeId: directGrantProj1b.PublicId,
			Grant:   directGrantProj1bRoleGrant,
		},

		// Grants from direct org1 to org2/proj2a/proj2b:
		{
			RoleId:  directGrantOrg2Role.PublicId,
			ScopeId: directGrantOrg2.PublicId,
			Grant:   directGrantOrg2RoleGrant,
		},
		{
			RoleId:  directGrantOrg2Role.PublicId,
			ScopeId: directGrantProj2a.PublicId,
			Grant:   directGrantOrg2RoleGrant,
		},
		{
			RoleId:  directGrantOrg2Role.PublicId,
			ScopeId: directGrantProj2b.PublicId,
			Grant:   directGrantOrg2RoleGrant,
		},
		// Grants from direct org 2 proj 2a:
		{
			RoleId:  directGrantProj2aRole.PublicId,
			ScopeId: directGrantProj2a.PublicId,
			Grant:   directGrantProj2aRoleGrant,
		},
		// Grant from direct org 2 proj 2 b:
		{
			RoleId:  directGrantProj2bRole.PublicId,
			ScopeId: directGrantProj2b.PublicId,
			Grant:   directGrantProj2bRoleGrant,
		},

		// Child grants from child org1 to proj1a/proj1b:
		{
			RoleId:  childGrantOrg1Role.PublicId,
			ScopeId: childGrantProj1a.PublicId,
			Grant:   childGrantOrg1RoleGrant,
		},
		{
			RoleId:  childGrantOrg1Role.PublicId,
			ScopeId: childGrantProj1b.PublicId,
			Grant:   childGrantOrg1RoleGrant,
		},
		// Child grants from child org2 to proj2a/proj2b:
		{
			RoleId:  childGrantOrg2Role.PublicId,
			ScopeId: childGrantProj2a.PublicId,
			Grant:   childGrantOrg2RoleGrant,
		},
		{
			RoleId:  childGrantOrg2Role.PublicId,
			ScopeId: childGrantProj2b.PublicId,
			Grant:   childGrantOrg2RoleGrant,
		},

		// Grants from global to every org:
		{
			RoleId:  childGrantGlobalRole.PublicId,
			ScopeId: noGrantOrg1.PublicId,
			Grant:   childGrantGlobalRoleGrant,
		},
		{
			RoleId:  childGrantGlobalRole.PublicId,
			ScopeId: noGrantOrg2.PublicId,
			Grant:   childGrantGlobalRoleGrant,
		},
		{
			RoleId:  childGrantGlobalRole.PublicId,
			ScopeId: directGrantOrg1.PublicId,
			Grant:   childGrantGlobalRoleGrant,
		},
		{
			RoleId:  childGrantGlobalRole.PublicId,
			ScopeId: directGrantOrg2.PublicId,
			Grant:   childGrantGlobalRoleGrant,
		},
		{
			RoleId:  childGrantGlobalRole.PublicId,
			ScopeId: childGrantOrg1.PublicId,
			Grant:   childGrantGlobalRoleGrant,
		},
		{
			RoleId:  childGrantGlobalRole.PublicId,
			ScopeId: childGrantOrg2.PublicId,
			Grant:   childGrantGlobalRoleGrant,
		},

		// Grants from global to every org and project:
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: noGrantOrg1.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: noGrantProj1.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: noGrantOrg2.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: noGrantProj2.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: directGrantOrg1.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: directGrantProj1a.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: directGrantProj1b.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: directGrantOrg2.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: directGrantProj2a.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: directGrantProj2b.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: childGrantOrg1.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: childGrantProj1a.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: childGrantProj1b.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: childGrantOrg2.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: childGrantProj2a.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
		{
			RoleId:  descendantGrantGlobalRole.PublicId,
			ScopeId: childGrantProj2b.PublicId,
			Grant:   descendantGrantGlobalRoleGrant,
		},
	}

	grantTuples, err := repo.GrantsForUser(ctx, user.PublicId)
	require.NoError(err)
	assert.ElementsMatch(grantTuples, expGrantTuples)
}
