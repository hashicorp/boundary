package iam

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddRoleGrants(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	_, proj := TestScopes(t, conn)
	role := TestRole(t, conn, proj.PublicId)
	createGrantsFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			g := fmt.Sprintf("id=hc_%d;actions=*", i)
			results = append(results, g)
		}
		return results
	}
	type args struct {
		roleId      string
		roleVersion int
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocRoleGrant()).Error)
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
				gotRoleGrant[r.PrivateId] = r
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
				roleGrant := gotRoleGrant[r.PrivateId]
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
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	const testLimit = 10
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper, WithLimit(testLimit))
	require.NoError(t, err)
	org, proj := TestScopes(t, conn)

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
			require.NoError(conn.Where("1=1").Delete(allocRole()).Error)
			role := TestRole(t, conn, tt.createScopeId)
			roleGrants := make([]string, 0, tt.createCnt)
			for i := 0; i < tt.createCnt; i++ {
				roleGrants = append(roleGrants, fmt.Sprintf("id=h_%d;actions=*", i))
			}
			testRoles, err := repo.AddRoleGrants(context.Background(), role.PublicId, int(role.Version), roleGrants, tt.args.opt...)
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
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	org, _ := TestScopes(t, conn)

	type args struct {
		role           *Role
		roleIdOverride *string
		createCnt      int
		deleteCnt      int
		opt            []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsErr       error
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
		/*
			{
				name: "valid-keeping-some",
				args: args{
					role:           TestRole(t, conn, org.PublicId),
					createUserCnt:  5,
					createGroupCnt: 5,
					deleteUserCnt:  2,
					deleteGroupCnt: 2,
				},
				wantRowsDeleted: 4,
				wantErr:         false,
			},
			{
				name: "no-deletes",
				args: args{
					role:           TestRole(t, conn, org.PublicId),
					createUserCnt:  5,
					createGroupCnt: 5,
				},
				wantRowsDeleted: 0,
				wantErr:         true,
				wantIsErr:       db.ErrInvalidParameter,
			},
			{
				name: "just-user-roles",
				args: args{
					role:          TestRole(t, conn, org.PublicId),
					createUserCnt: 5,
					deleteUserCnt: 5,
				},
				wantRowsDeleted: 5,
				wantErr:         false,
			},
			{
				name: "just-group-roles",
				args: args{
					role:           TestRole(t, conn, org.PublicId),
					createGroupCnt: 5,
					deleteGroupCnt: 5,
				},
				wantRowsDeleted: 5,
				wantErr:         false,
			},
			{
				name: "not-found",
				args: args{
					role:           TestRole(t, conn, org.PublicId),
					roleIdOverride: func() *string { id := testId(t); return &id }(),
					createUserCnt:  5,
					createGroupCnt: 5,
					deleteUserCnt:  5,
					deleteGroupCnt: 5,
				},
				wantRowsDeleted: 0,
				wantErr:         true,
			},
			{
				name: "missing-role-id",
				args: args{
					role:           TestRole(t, conn, org.PublicId),
					roleIdOverride: func() *string { id := ""; return &id }(),
					createUserCnt:  5,
					createGroupCnt: 5,
					deleteUserCnt:  5,
					deleteGroupCnt: 5,
				},
				wantRowsDeleted: 0,
				wantErr:         true,
				wantIsErr:       db.ErrInvalidParameter,
			},
		*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocRoleGrant()).Error)
			grants := make([]*RoleGrant, 0, tt.args.createCnt)
			grantStrings := make([]string, 0, tt.args.createCnt)
			for i := 0; i < tt.args.createCnt; i++ {
				g, err := NewRoleGrant(tt.args.role.PublicId, fmt.Sprintf("actions=*;id=s_%d", i), tt.args.opt...)
				require.NoError(err)
				id, err := newRoleGrantId()
				require.NoError(err)
				g.PrivateId = id
				grantStrings = append(grantStrings, g.UserGrant)
				grants = append(grants, g)
			}
			roleGrants, err := repo.AddRoleGrants(context.Background(), tt.args.role.PublicId, 1, grantStrings, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.args.createCnt, len(roleGrants))

			deleteIds := make([]string, 0, tt.args.deleteCnt)
			deleteGrants := make([]string, 0, tt.args.deleteCnt)
			for i := 0; i < tt.args.deleteCnt; i++ {
				deleteIds = append(deleteIds, grants[i].PrivateId)
				deleteGrants = append(deleteGrants, fmt.Sprintf("id=s_%d;actions=*", i))
			}

			var roleId string
			switch {
			case tt.args.roleIdOverride != nil:
				roleId = *tt.args.roleIdOverride
			default:
				roleId = tt.args.role.PublicId
			}
			deletedRows, err := repo.DeleteRoleGrants(context.Background(), roleId, 2, deleteGrants, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				if tt.wantIsErr != nil {
					assert.Truef(errors.Is(err, tt.wantIsErr), "unexpected error %s", err.Error())
				}
				err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)

			roleGrants = []*RoleGrant{}
			require.NoError(repo.reader.SearchWhere(context.Background(), &roleGrants, "role_id = ?", []interface{}{roleId}))
			found := map[string]bool{}
			for _, rg := range roleGrants {
				found[rg.PrivateId] = true
			}
			for _, i := range deleteIds {
				assert.False(found[i])
			}

			err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
