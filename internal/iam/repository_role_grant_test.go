// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
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
		name               string
		createCnt          int
		createGrantScopeId string
		args               args
		wantCnt            int
		wantErr            bool
	}{
		{
			name:               "no-limit",
			createCnt:          repo.defaultLimit + 2,
			createGrantScopeId: org.PublicId,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 2,
			wantErr: false,
		},
		{
			name:               "no-limit-proj-group",
			createCnt:          repo.defaultLimit + 2,
			createGrantScopeId: proj.PublicId,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 2,
			wantErr: false,
		},
		{
			name:               "default-limit",
			createCnt:          repo.defaultLimit + 2,
			createGrantScopeId: org.PublicId,
			wantCnt:            repo.defaultLimit,
			wantErr:            false,
		},
		{
			name:               "custom-limit",
			createCnt:          repo.defaultLimit + 2,
			createGrantScopeId: org.PublicId,
			args: args{
				opt: []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:               "bad-role-id",
			createCnt:          2,
			createGrantScopeId: org.PublicId,
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
			role := TestRole(t, conn, tt.createGrantScopeId)
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
		prng := rand.New(rand.NewSource(time.Now().UnixNano()))
		for _, rgw := range grants {
			rgw.enabled = prng.Int()%2 == 0
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

	t.Run("db-grants", func(t *testing.T) {
		// Here we should see exactly what the DB has returned, before we do some
		// local exploding of grants and grant scopes
		expMultiGrantTuples := []multiGrantTuple{
			// No grants from noOrg/noProj
			// Direct org1/2:
			{
				RoleId:            directGrantOrg1Role.PublicId,
				RoleScopeId:       directGrantOrg1.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeIds:     globals.GrantScopeThis,
				Grants:            strings.Join([]string{directGrantOrg1RoleGrant1, directGrantOrg1RoleGrant2}, "^"),
			},
			{
				RoleId:            directGrantOrg2Role.PublicId,
				RoleScopeId:       directGrantOrg2.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeIds:     strings.Join([]string{globals.GrantScopeThis, directGrantProj2a.PublicId}, "^"),
				Grants:            strings.Join([]string{directGrantOrg2RoleGrant1, directGrantOrg2RoleGrant2}, "^"),
			},
			// Proj orgs 1/2:
			{
				RoleId:            directGrantProj1aRole.PublicId,
				RoleScopeId:       directGrantProj1a.PublicId,
				RoleParentScopeId: directGrantOrg1.PublicId,
				GrantScopeIds:     globals.GrantScopeThis,
				Grants:            directGrantProj1aRoleGrant,
			},
			{
				RoleId:            directGrantProj1bRole.PublicId,
				RoleScopeId:       directGrantProj1b.PublicId,
				RoleParentScopeId: directGrantOrg1.PublicId,
				GrantScopeIds:     globals.GrantScopeThis,
				Grants:            directGrantProj1bRoleGrant,
			},
			{
				RoleId:            directGrantProj2aRole.PublicId,
				RoleScopeId:       directGrantProj2a.PublicId,
				RoleParentScopeId: directGrantOrg2.PublicId,
				GrantScopeIds:     globals.GrantScopeThis,
				Grants:            directGrantProj2aRoleGrant,
			},
			{
				RoleId:            directGrantProj2bRole.PublicId,
				RoleScopeId:       directGrantProj2b.PublicId,
				RoleParentScopeId: directGrantOrg2.PublicId,
				GrantScopeIds:     globals.GrantScopeThis,
				Grants:            directGrantProj2bRoleGrant,
			},
			// Child grants from orgs 1/2:
			{
				RoleId:            childGrantOrg1Role.PublicId,
				RoleScopeId:       childGrantOrg1.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeIds:     globals.GrantScopeChildren,
				Grants:            childGrantOrg1RoleGrant,
			},
			{
				RoleId:            childGrantOrg2Role.PublicId,
				RoleScopeId:       childGrantOrg2.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeIds:     globals.GrantScopeChildren,
				Grants:            strings.Join([]string{childGrantOrg2RoleGrant1, childGrantOrg2RoleGrant2}, "^"),
			},
			// Children of global and descendants of global
			{
				RoleId:        descendantGrantGlobalRole.PublicId,
				RoleScopeId:   scope.Global.String(),
				GrantScopeIds: globals.GrantScopeDescendants,
				Grants:        descendantGrantGlobalRoleGrant,
			},
			{
				RoleId:        childGrantGlobalRole.PublicId,
				RoleScopeId:   scope.Global.String(),
				GrantScopeIds: globals.GrantScopeChildren,
				Grants:        childGrantGlobalRoleGrant,
			},
		}
		for i, tuple := range expMultiGrantTuples {
			tuple.testStableSort()
			expMultiGrantTuples[i] = tuple
		}
		multiGrantTuplesCache := new([]multiGrantTuple)
		_, err := repo.GrantsForUser(ctx, user.PublicId, withTestCacheMultiGrantTuples(multiGrantTuplesCache))
		require.NoError(t, err)

		// log.Println("multiGrantTuplesCache", pretty.Sprint(*multiGrantTuplesCache))
		assert.ElementsMatch(t, *multiGrantTuplesCache, expMultiGrantTuples)
	})

	t.Run("exploded-grants", func(t *testing.T) {
		// We expect to see:
		//
		// * No grants from noOrg/noProj
		// * Grants from direct orgs/projs:
		//   * directGrantOrg1/directGrantOrg2 on org and respective projects (6 grants total per org)
		//   * directGrantProj on respective projects (4 grants total)
		expGrantTuples := []perms.GrantTuple{
			// No grants from noOrg/noProj
			// Grants from direct org1 to org1/proj1a/proj1b:
			{
				RoleId:            directGrantOrg1Role.PublicId,
				RoleScopeId:       directGrantOrg1.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      directGrantOrg1.PublicId,
				Grant:             directGrantOrg1RoleGrant1,
			},
			{
				RoleId:            directGrantOrg1Role.PublicId,
				RoleScopeId:       directGrantOrg1.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      directGrantOrg1.PublicId,
				Grant:             directGrantOrg1RoleGrant2,
			},
			// Grants from direct org 1 proj 1a:
			{
				RoleId:            directGrantProj1aRole.PublicId,
				RoleScopeId:       directGrantProj1a.PublicId,
				RoleParentScopeId: directGrantOrg1.PublicId,
				GrantScopeId:      directGrantProj1a.PublicId,
				Grant:             directGrantProj1aRoleGrant,
			},
			// Grant from direct org 1 proj 1 b:
			{
				RoleId:            directGrantProj1bRole.PublicId,
				RoleScopeId:       directGrantProj1b.PublicId,
				RoleParentScopeId: directGrantOrg1.PublicId,
				GrantScopeId:      directGrantProj1b.PublicId,
				Grant:             directGrantProj1bRoleGrant,
			},

			// Grants from direct org2 to org2/proj2a/proj2b:
			{
				RoleId:            directGrantOrg2Role.PublicId,
				RoleScopeId:       directGrantOrg2.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      directGrantOrg2.PublicId,
				Grant:             directGrantOrg2RoleGrant1,
			},
			{
				RoleId:            directGrantOrg2Role.PublicId,
				RoleScopeId:       directGrantOrg2.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      directGrantProj2a.PublicId,
				Grant:             directGrantOrg2RoleGrant1,
			},
			{
				RoleId:            directGrantOrg2Role.PublicId,
				RoleScopeId:       directGrantOrg2.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      directGrantOrg2.PublicId,
				Grant:             directGrantOrg2RoleGrant2,
			},
			{
				RoleId:            directGrantOrg2Role.PublicId,
				RoleScopeId:       directGrantOrg2.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      directGrantProj2a.PublicId,
				Grant:             directGrantOrg2RoleGrant2,
			},
			// Grants from direct org 2 proj 2a:
			{
				RoleId:            directGrantProj2aRole.PublicId,
				RoleScopeId:       directGrantProj2a.PublicId,
				RoleParentScopeId: directGrantOrg2.PublicId,
				GrantScopeId:      directGrantProj2a.PublicId,
				Grant:             directGrantProj2aRoleGrant,
			},
			// Grant from direct org 2 proj 2 b:
			{
				RoleId:            directGrantProj2bRole.PublicId,
				RoleScopeId:       directGrantProj2b.PublicId,
				RoleParentScopeId: directGrantOrg2.PublicId,
				GrantScopeId:      directGrantProj2b.PublicId,
				Grant:             directGrantProj2bRoleGrant,
			},
			// Child grants from child org1 to proj1a/proj1b:
			{
				RoleId:            childGrantOrg1Role.PublicId,
				RoleScopeId:       childGrantOrg1.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      globals.GrantScopeChildren,
				Grant:             childGrantOrg1RoleGrant,
			},
			// Child grants from child org2 to proj2a/proj2b:
			{
				RoleId:            childGrantOrg2Role.PublicId,
				RoleScopeId:       childGrantOrg2.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      globals.GrantScopeChildren,
				Grant:             childGrantOrg2RoleGrant1,
			},
			{
				RoleId:            childGrantOrg2Role.PublicId,
				RoleScopeId:       childGrantOrg2.PublicId,
				RoleParentScopeId: scope.Global.String(),
				GrantScopeId:      globals.GrantScopeChildren,
				Grant:             childGrantOrg2RoleGrant2,
			},

			// Grants from global to every org:
			{
				RoleId:       childGrantGlobalRole.PublicId,
				RoleScopeId:  scope.Global.String(),
				GrantScopeId: globals.GrantScopeChildren,
				Grant:        childGrantGlobalRoleGrant,
			},

			// Grants from global to every org and project:
			{
				RoleId:       descendantGrantGlobalRole.PublicId,
				RoleScopeId:  scope.Global.String(),
				GrantScopeId: globals.GrantScopeDescendants,
				Grant:        descendantGrantGlobalRoleGrant,
			},
		}

		multiGrantTuplesCache := new([]multiGrantTuple)
		grantTuples, err := repo.GrantsForUser(ctx, user.PublicId, withTestCacheMultiGrantTuples(multiGrantTuplesCache))
		require.NoError(t, err)
		assert.ElementsMatch(t, grantTuples, expGrantTuples)
	})

	t.Run("acl-grants", func(t *testing.T) {
		grantTuples, err := repo.GrantsForUser(ctx, user.PublicId)
		require.NoError(t, err)
		grants := make([]perms.Grant, 0, len(grantTuples))
		for _, gt := range grantTuples {
			grant, err := perms.Parse(ctx, gt)
			require.NoError(t, err)
			grants = append(grants, grant)
		}
		acl := perms.NewACL(grants...)

		t.Run("descendant-grants", func(t *testing.T) {
			descendantGrants := acl.DescendantsGrants()
			expDescendantGrants := []perms.AclGrant{
				{
					RoleScopeId:  scope.Global.String(),
					GrantScopeId: globals.GrantScopeDescendants,
					Id:           "*",
					Type:         resource.Credential,
					ActionSet:    perms.ActionSet{action.All: true},
				},
			}
			assert.ElementsMatch(t, descendantGrants, expDescendantGrants)
		})

		t.Run("child-grants", func(t *testing.T) {
			childrenGrants := acl.ChildrenScopeGrantMap()
			expChildrenGrants := map[string][]perms.AclGrant{
				childGrantOrg1.PublicId: {
					{
						RoleScopeId:       childGrantOrg1.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      globals.GrantScopeChildren,
						Id:                "*",
						Type:              resource.HostSet,
						ActionSet:         perms.ActionSet{action.AddHosts: true, action.RemoveHosts: true},
					},
				},
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
				scope.Global.String(): {
					{
						RoleScopeId:  scope.Global.String(),
						GrantScopeId: globals.GrantScopeChildren,
						Id:           "*",
						Type:         resource.Account,
						ActionSet:    perms.ActionSet{action.All: true},
					},
				},
			}
			assert.Len(t, childrenGrants, len(expChildrenGrants))
			for k, v := range childrenGrants {
				assert.ElementsMatch(t, v, expChildrenGrants[k])
			}
		})

		t.Run("direct-grants", func(t *testing.T) {
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
				directGrantProj1a.PublicId: {
					{
						RoleScopeId:       directGrantProj1a.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1a.PublicId,
						Id:                "*",
						Type:              resource.Target,
						ActionSet:         perms.ActionSet{action.AuthorizeSession: true, action.Read: true},
					},
				},
				directGrantProj1b.PublicId: {
					{
						RoleScopeId:       directGrantProj1b.PublicId,
						RoleParentScopeId: directGrantOrg1.PublicId,
						GrantScopeId:      directGrantProj1b.PublicId,
						Id:                "*",
						Type:              resource.Session,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantOrg2.PublicId: {
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              resource.User,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantOrg2.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
				},
				directGrantProj2a.PublicId: {
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              resource.User,
						ActionSet:         perms.ActionSet{action.All: true},
					},
					{
						RoleScopeId:       directGrantOrg2.PublicId,
						RoleParentScopeId: scope.Global.String(),
						GrantScopeId:      directGrantProj2a.PublicId,
						Id:                "*",
						Type:              resource.Group,
						ActionSet:         perms.ActionSet{action.List: true, action.Read: true},
					},
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
			/*
				log.Println("org1", directGrantOrg1.PublicId)
				log.Println("proj1a", directGrantProj1a.PublicId)
				log.Println("proj1b", directGrantProj1b.PublicId)
				log.Println("org2", directGrantOrg2.PublicId)
				log.Println("proj2a", directGrantProj2a.PublicId)
				log.Println("proj2b", directGrantProj2b.PublicId)
			*/
			assert.Len(t, directGrants, len(expDirectGrants))
			for k, v := range directGrants {
				assert.ElementsMatch(t, v, expDirectGrants[k])
			}
		})
	})
	t.Run("real-world", func(t *testing.T) {
		// These tests cases crib from the initial setup of the grants, and
		// include a number of cases to ensure the ones that should work do and
		// various that should not do not
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
					Id:            "u_abcd1234",
					Type:          resource.User,
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
					Id:            "u_abcd1234",
					Type:          resource.User,
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
					Id:            "g_abcd1234",
					Type:          resource.Group,
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
					Id:            "u_abcd1234",
					Type:          resource.User,
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
					Id:            "s_abcd1234",
					Type:          resource.Session,
					ParentScopeId: scope.Global.String(),
				},
				act: action.CancelSelf,
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
					Id:            "hsst_abcd1234",
					Type:          resource.HostSet,
					ParentScopeId: scope.Global.String(),
				},
				act: action.AddHosts,
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
			},
			)
		}
		// These test cases are global descendants grants
		{
			testCases = append(testCases, testCase{
				name: "descendants-a",
				res: perms.Resource{
					ScopeId: scope.Global.String(),
					Id:      "cs_abcd1234",
					Type:    resource.Credential,
				},
				act: action.Update,
			}, testCase{
				name: "descendants-b",
				res: perms.Resource{
					ScopeId:       noGrantProj1.PublicId,
					Id:            "cs_abcd1234",
					Type:          resource.Credential,
					ParentScopeId: noGrantOrg1.PublicId,
				},
				act:        action.Update,
				shouldWork: true,
			}, testCase{
				name: "descendants-c",
				res: perms.Resource{
					ScopeId:       directGrantOrg2.PublicId,
					Id:            "cs_abcd1234",
					Type:          resource.Credential,
					ParentScopeId: scope.Global.String(),
				},
				act:        action.Update,
				shouldWork: true,
			}, testCase{
				name: "descendants-d",
				res: perms.Resource{
					ScopeId:       directGrantProj1a.PublicId,
					Id:            "cs_abcd1234",
					Type:          resource.Credential,
					ParentScopeId: directGrantOrg1.PublicId,
				},
				act:        action.Update,
				shouldWork: true,
			}, testCase{
				name: "descendants-e",
				res: perms.Resource{
					ScopeId:       directGrantProj1a.PublicId,
					Id:            "cs_abcd1234",
					Type:          resource.Credential,
					ParentScopeId: directGrantOrg1.PublicId,
				},
				act:        action.Update,
				shouldWork: true,
			}, testCase{
				name: "descendants-f",
				res: perms.Resource{
					ScopeId:       directGrantProj2b.PublicId,
					Id:            "cs_abcd1234",
					Type:          resource.Credential,
					ParentScopeId: directGrantOrg2.PublicId,
				},
				act:        action.Update,
				shouldWork: true,
			},
			)
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				grantTuples, err := repo.GrantsForUser(ctx, user.PublicId)
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
	})
}
