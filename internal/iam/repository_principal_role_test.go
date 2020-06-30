package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddPrincipalRoles(t *testing.T) {
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
	org, proj := TestScopes(t, conn)
	role := TestRole(t, conn, proj.PublicId)
	createUsersFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			u := TestUser(t, conn, org.PublicId)
			results = append(results, u.PublicId)
		}
		return results
	}
	createGrpsFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			g := TestGroup(t, conn, proj.PublicId)
			results = append(results, g.PublicId)
		}
		return results
	}
	type args struct {
		roleId      string
		roleVersion int
		userIds     []string
		groupIds    []string
		opt         []Option
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "valid-both-users-and-groups",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1,
				userIds:     createUsersFn(),
				groupIds:    createGrpsFn(),
			},
			wantErr: false,
		},
		{
			name: "valid-just-groups",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 2,
				userIds:     nil,
				groupIds:    createGrpsFn(),
			},
			wantErr: false,
		},
		{
			name: "valid-just-users",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 3,
				userIds:     createUsersFn(),
				groupIds:    nil,
			},
			wantErr: false,
		},
		{
			name: "bad-version",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1000,
				userIds:     createUsersFn(),
				groupIds:    createGrpsFn(),
			},
			wantErr: true,
		},
		{
			name: "no-principals",
			args: args{
				roleId:      role.PublicId,
				roleVersion: 1,
				userIds:     nil,
				groupIds:    nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocUserRole()).Error)
			require.NoError(conn.Where("1=1").Delete(allocGroupRole()).Error)
			got, err := repo.AddPrincipalRoles(context.Background(), tt.args.roleId, tt.args.roleVersion, tt.args.userIds, tt.args.groupIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrIs != nil {
					assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			gotPrincipal := map[string]PrincipalRole{}
			for _, r := range got {
				gotPrincipal[r.GetPrincipalId()] = r
			}
			for _, id := range tt.args.userIds {
				assert.NotEmpty(gotPrincipal[id])
				u, err := repo.LookupUser(context.Background(), id)
				assert.NoError(err)
				assert.Equal(id, u.PublicId)
			}
			for _, id := range tt.args.groupIds {
				assert.NotEmpty(gotPrincipal[id])
				g, err := repo.LookupGroup(context.Background(), id)
				assert.NoError(err)
				assert.Equal(id, g.PublicId)
			}
			err = db.TestVerifyOplog(t, rw, role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			foundRoles, err := repo.ListPrincipalRoles(context.Background(), role.PublicId)
			require.NoError(err)
			for _, r := range foundRoles {
				assert.NotEmpty(gotPrincipal[r.GetPrincipalId()])
				assert.Equal(gotPrincipal[r.GetPrincipalId()].GetRoleId(), r.GetRoleId())
				assert.Equal(gotPrincipal[r.GetPrincipalId()].GetScopeId(), r.GetScopeId())
				assert.Equal(gotPrincipal[r.GetPrincipalId()].GetType(), r.GetType())
			}

		})
	}
}

func TestRepository_ListPrincipalRoles(t *testing.T) {
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
			userRoles := make([]string, 0, tt.createCnt)
			groupRoles := make([]string, 0, tt.createCnt)
			for i := 0; i < tt.createCnt/2; i++ {
				u := TestUser(t, conn, org.PublicId)
				userRoles = append(userRoles, u.PublicId)
				g := TestGroup(t, conn, tt.createScopeId)
				groupRoles = append(groupRoles, g.PublicId)
			}
			testRoles, err := repo.AddPrincipalRoles(context.Background(), role.PublicId, int(role.Version), userRoles, groupRoles, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.createCnt, len(testRoles))

			var roleId string
			switch {
			case tt.args.withRoleId != "":
				roleId = tt.args.withRoleId
			default:
				roleId = role.PublicId
			}
			got, err := repo.ListPrincipalRoles(context.Background(), roleId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}

func TestRepository_DeletePrincipalRoles(t *testing.T) {
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
		createUserCnt  int
		createGroupCnt int
		deleteUserCnt  int
		deleteGroupCnt int
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
				role:           TestRole(t, conn, org.PublicId),
				createUserCnt:  5,
				createGroupCnt: 5,
				deleteUserCnt:  5,
				deleteGroupCnt: 5,
			},
			wantRowsDeleted: 10,
			wantErr:         false,
		},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			userIds := make([]string, 0, tt.args.createUserCnt)
			for i := 0; i < tt.args.createUserCnt; i++ {
				u := TestUser(t, conn, org.PublicId)
				userIds = append(userIds, u.PublicId)
			}
			groupIds := make([]string, 0, tt.args.createGroupCnt)
			for i := 0; i < tt.args.createGroupCnt; i++ {
				g := TestGroup(t, conn, tt.args.role.ScopeId)
				groupIds = append(groupIds, g.PublicId)
			}
			principalRoles, err := repo.AddPrincipalRoles(context.Background(), tt.args.role.PublicId, 1, userIds, groupIds, tt.args.opt...)
			require.NoError(err)
			assert.Equal(tt.args.createUserCnt+tt.args.createGroupCnt, len(principalRoles))

			deleteUserIds := make([]string, 0, tt.args.deleteUserCnt)
			for i := 0; i < tt.args.deleteUserCnt; i++ {
				deleteUserIds = append(deleteUserIds, userIds[i])
			}
			deleteGroupIds := make([]string, 0, tt.args.deleteGroupCnt)
			for i := 0; i < tt.args.deleteGroupCnt; i++ {
				deleteGroupIds = append(deleteGroupIds, groupIds[i])
			}
			var roleId string
			switch {
			case tt.args.roleIdOverride != nil:
				roleId = *tt.args.roleIdOverride
			default:
				roleId = tt.args.role.PublicId
			}
			deletedRows, err := repo.DeletePrincipalRoles(context.Background(), roleId, 2, deleteUserIds, deleteGroupIds, tt.args.opt...)
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

			err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
