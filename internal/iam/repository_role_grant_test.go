// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
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
				g, err := NewRoleGrant(ctx, tt.args.role.PublicId, fmt.Sprintf("actions=*;id=s_%d", i), tt.args.opt...)
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
