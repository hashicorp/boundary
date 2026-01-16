// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddPrincipalRoles(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	staticOrg, staticProj := TestScopes(t, repo)
	globalRole := TestRole(t, conn, globals.GlobalPrefix)
	orgRole := TestRole(t, conn, staticOrg.PublicId)
	projRole := TestRole(t, conn, staticProj.PublicId)
	createScopesFn := func() (orgs []string, projects []string) {
		for i := 0; i < 5; i++ {
			org, proj := TestScopes(t, repo)
			orgs = append(orgs, org.PublicId)
			projects = append(projects, proj.PublicId)
		}
		return orgs, projects
	}
	createUsersFn := func(orgs []string) []string {
		results := []string{}
		for org := 0; org < 5; org++ {
			u := TestUser(t, repo, orgs[org])
			results = append(results, u.PublicId)
		}
		return results
	}
	createGrpsFn := func(orgs, projects []string) []string {
		results := []string{}
		for org := 0; org < 5; org++ {
			g := TestGroup(t, conn, orgs[org])
			results = append(results, g.PublicId)
			for proj := 0; proj < 5; proj++ {
				g := TestGroup(t, conn, projects[proj])
				results = append(results, g.PublicId)
			}
		}
		return results
	}
	type args struct {
		roleVersion     uint32
		wantUserIds     bool
		specificUserIds []string
		wantGroupIds    bool
		opt             []Option
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
				roleVersion:  1,
				wantUserIds:  true,
				wantGroupIds: true,
			},
			wantErr: false,
		},
		{
			name: "valid-just-groups",
			args: args{
				roleVersion:  2,
				wantGroupIds: true,
			},
			wantErr: false,
		},
		{
			name: "valid-just-users",
			args: args{
				roleVersion: 3,
				wantUserIds: true,
			},
			wantErr: false,
		},
		{
			name: "bad-version",
			args: args{
				roleVersion:  1000,
				wantUserIds:  true,
				wantGroupIds: true,
			},
			wantErr: true,
		},
		{
			name: "zero-version",
			args: args{
				roleVersion:  0,
				wantUserIds:  true,
				wantGroupIds: true,
			},
			wantErr: true,
		},
		{
			name: "no-principals",
			args: args{
				roleVersion: 1,
			},
			wantErr: true,
		},
		{
			name: "recovery-user",
			args: args{
				roleVersion:     1,
				specificUserIds: []string{globals.RecoveryUserId},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() any { r := allocUserRole(); return &r }(), "1=1")
			db.TestDeleteWhere(t, conn, func() any { g := allocGroupRole(); return &g }(), "1=1")
			orgs, projects := createScopesFn()
			var userIds, groupIds []string

			for _, roleId := range []string{globalRole.PublicId, orgRole.PublicId, projRole.PublicId} {
				origRole, _, _, _, err := repo.LookupRole(context.Background(), roleId)
				require.NoError(err)

				if tt.args.wantUserIds {
					userIds = createUsersFn(orgs)
					u := TestUser(t, repo, staticOrg.PublicId)
					userIds = append(userIds, u.PublicId)
				}
				if tt.args.wantGroupIds {
					groupIds = createGrpsFn(orgs, projects)
					g := TestGroup(t, conn, staticProj.PublicId)
					groupIds = append(groupIds, g.PublicId)
				}
				if len(tt.args.specificUserIds) > 0 {
					userIds = tt.args.specificUserIds
				}
				principalIds := append(userIds, groupIds...)
				got, err := repo.AddPrincipalRoles(context.Background(), roleId, tt.args.roleVersion, principalIds, tt.args.opt...)
				if tt.wantErr {
					require.Error(err)
					if tt.wantErrIs != nil {
						assert.Truef(errors.Is(err, tt.wantErrIs), "unexpected error %s", err.Error())
					}
					return
				}
				require.NoError(err)
				gotPrincipal := map[string]*PrincipalRole{}
				for _, r := range got {
					gotPrincipal[r.ScopedPrincipalId] = r
				}
				err = db.TestVerifyOplog(t, rw, roleId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
				assert.NoError(err)

				foundRoles, err := repo.ListPrincipalRoles(context.Background(), roleId)
				require.NoError(err)
				for _, r := range foundRoles {
					principalId := r.ScopedPrincipalId
					require.NoError(err)
					assert.NotEmpty(gotPrincipal[principalId])
					assert.Equal(gotPrincipal[principalId].GetRoleId(), r.GetRoleId())
					assert.Equal(gotPrincipal[principalId].GetPrincipalScopeId(), r.GetPrincipalScopeId())
					assert.Equal(gotPrincipal[principalId].GetType(), r.GetType())
				}

				r, _, _, _, err := repo.LookupRole(context.Background(), roleId)
				require.NoError(err)
				assert.Equal(tt.args.roleVersion+1, r.Version)
				assert.Equal(origRole.Version, r.Version-1)
				t.Logf("roleScope: %v and origVersion/newVersion: %d/%d", r.ScopeId, origRole.Version, r.Version)
			}
		})
	}
}

func TestRepository_ListPrincipalRoles(t *testing.T) {
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
			db.TestDeleteWhere(t, conn, func() any { i := allocGlobalRole(); return &i }(), "1=1")
			db.TestDeleteWhere(t, conn, func() any { i := allocOrgRole(); return &i }(), "1=1")
			db.TestDeleteWhere(t, conn, func() any { i := allocProjectRole(); return &i }(), "1=1")
			role := TestRole(t, conn, tt.createScopeId)
			userRoles := make([]string, 0, tt.createCnt)
			groupRoles := make([]string, 0, tt.createCnt)
			for i := 0; i < tt.createCnt/2; i++ {
				u := TestUser(t, repo, org.PublicId)
				userRoles = append(userRoles, u.PublicId)
				g := TestGroup(t, conn, tt.createScopeId)
				groupRoles = append(groupRoles, g.PublicId)
			}
			principalIds := append(userRoles, groupRoles...)
			testRoles, err := repo.AddPrincipalRoles(context.Background(), role.PublicId, role.Version, principalIds, tt.args.opt...)
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)

	type args struct {
		role                *Role
		roleIdOverride      *string
		roleVersionOverride *uint32
		createUserCnt       int
		createGroupCnt      int
		deleteUserCnt       int
		deleteGroupCnt      int
		opt                 []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsErr       errors.Code
	}{
		{
			name: "valid-global",
			args: args{
				role:           TestRole(t, conn, globals.GlobalPrefix),
				createUserCnt:  5,
				createGroupCnt: 5,
				deleteUserCnt:  5,
				deleteGroupCnt: 5,
			},
			wantRowsDeleted: 10,
			wantErr:         false,
		},
		{
			name: "valid-org",
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
			name: "valid-proj",
			args: args{
				role:           TestRole(t, conn, proj.PublicId),
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
			name: "no-deletes",
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				createUserCnt:  5,
				createGroupCnt: 5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
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
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "zero-version",
			args: args{
				role:                TestRole(t, conn, org.PublicId),
				roleVersionOverride: func() *uint32 { v := uint32(0); return &v }(),
				createUserCnt:       5,
				createGroupCnt:      5,
				deleteUserCnt:       5,
				deleteGroupCnt:      5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsErr:       errors.InvalidParameter,
		},
		{
			name: "bad-version",
			args: args{
				role:                TestRole(t, conn, org.PublicId),
				roleVersionOverride: func() *uint32 { v := uint32(1000); return &v }(),
				createUserCnt:       5,
				createGroupCnt:      5,
				deleteUserCnt:       5,
				deleteGroupCnt:      5,
			},
			wantRowsDeleted: 0,
			wantErr:         true,
		},
	}
	createScopesFn := func() (orgs []string, projects []string) {
		for i := 0; i < 5; i++ {
			org, proj := TestScopes(t, repo)
			orgs = append(orgs, org.PublicId)
			projects = append(projects, proj.PublicId)
		}
		return orgs, projects
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orgs, projects := createScopesFn()
			userIds := make([]string, 0, tt.args.createUserCnt)
			if tt.args.createUserCnt > 0 {
				u := TestUser(t, repo, org.PublicId)
				userIds = append(userIds, u.PublicId)
				for i := 0; i < tt.args.createUserCnt-1; i++ {
					u := TestUser(t, repo, orgs[i])
					userIds = append(userIds, u.PublicId)
				}
			}
			groupIds := make([]string, 0, tt.args.createGroupCnt)
			if tt.args.createGroupCnt > 0 {
				g := TestGroup(t, conn, org.PublicId)
				groupIds = append(groupIds, g.PublicId)
				for i := 0; i < tt.args.createGroupCnt-1; i++ {
					g := TestGroup(t, conn, projects[i])
					groupIds = append(groupIds, g.PublicId)
				}
			}
			principalIds := append(userIds, groupIds...)
			principalRoles, err := repo.AddPrincipalRoles(context.Background(), tt.args.role.PublicId, 1, principalIds, tt.args.opt...)
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
			var roleVersion uint32
			switch {
			case tt.args.roleVersionOverride != nil:
				roleVersion = *tt.args.roleVersionOverride
			default:
				roleVersion = 2
			}
			principalIds = append(deleteUserIds, deleteGroupIds...)
			deletedRows, err := repo.DeletePrincipalRoles(context.Background(), roleId, roleVersion, principalIds, tt.args.opt...)
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

			err = db.TestVerifyOplog(t, rw, tt.args.role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_SetPrincipalRoles(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)

	org, proj := TestScopes(t, repo)
	testUser := TestUser(t, repo, org.PublicId)
	testGrp := TestGroup(t, conn, proj.PublicId)

	createUsersFn := func() []string {
		results := []string{}
		for i := 0; i < 5; i++ {
			u := TestUser(t, repo, org.PublicId)
			results = append(results, u.PublicId)
		}
		results = append(results, globals.AnonymousUserId)
		results = append(results, globals.AnyAuthenticatedUserId)
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
	setupFn := func(role *Role) ([]string, []string) {
		users := createUsersFn()
		grps := createGrpsFn()
		var err error
		_, err = repo.AddPrincipalRoles(context.Background(), role.PublicId, 1, append(users, grps...))
		require.NoError(t, err)
		return users, grps
	}
	type args struct {
		role           *Role
		roleVersion    uint32
		userIds        []string
		groupIds       []string
		addToOrigUsers bool
		addToOrigGrps  bool
		opt            []Option
	}
	tests := []struct {
		name             string
		setup            func(*Role) ([]string, []string)
		args             args
		wantAffectedRows int
		wantErr          bool
	}{
		{
			name:  "clear-global",
			setup: setupFn,
			args: args{
				role:        TestRole(t, conn, globals.GlobalPrefix),
				roleVersion: 2, // yep, since setupFn will increment it to 2
				userIds:     []string{},
				groupIds:    []string{},
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
		{
			name:  "clear-org",
			setup: setupFn,
			args: args{
				role:        TestRole(t, conn, org.PublicId),
				roleVersion: 2, // yep, since setupFn will increment it to 2
				userIds:     []string{},
				groupIds:    []string{},
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
		{
			name:  "clear-proj",
			setup: setupFn,
			args: args{
				role:        TestRole(t, conn, proj.PublicId),
				roleVersion: 2, // yep, since setupFn will increment it to 2
				userIds:     []string{},
				groupIds:    []string{},
			},
			wantErr:          false,
			wantAffectedRows: 12,
		},
		{
			name:  "global no change",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, globals.GlobalPrefix),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{},
				groupIds:       []string{},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr:          false,
			wantAffectedRows: 0,
		},
		{
			name:  "org no change",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{},
				groupIds:       []string{},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr:          false,
			wantAffectedRows: 0,
		},
		{
			name:  "proj no change",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, proj.PublicId),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{},
				groupIds:       []string{},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr:          false,
			wantAffectedRows: 0,
		},
		{
			name:  "global add users and grps",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, globals.GlobalPrefix),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr:          false,
			wantAffectedRows: 2,
		},
		{
			name:  "org add users and grps",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr:          false,
			wantAffectedRows: 2,
		},
		{
			name:  "proj add users and grps",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, proj.PublicId),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr:          false,
			wantAffectedRows: 2,
		},
		{
			name:  "global add users and grps with zero version",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, globals.GlobalPrefix),
				roleVersion:    0, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr: true,
		},
		{
			name:  "org add users and grps with zero version",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				roleVersion:    0, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr: true,
		},
		{
			name:  "proj add users and grps with zero version",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, proj.PublicId),
				roleVersion:    0, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: true,
				addToOrigGrps:  true,
			},
			wantErr: true,
		},
		{
			name:  "global remove existing and add users and grps",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, globals.GlobalPrefix),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: false,
				addToOrigGrps:  false,
			},
			wantErr:          false,
			wantAffectedRows: 14,
		},
		{
			name:  "org remove existing and add users and grps",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, org.PublicId),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: false,
				addToOrigGrps:  false,
			},
			wantErr:          false,
			wantAffectedRows: 14,
		},
		{
			name:  "proj remove existing and add users and grps",
			setup: setupFn,
			args: args{
				role:           TestRole(t, conn, proj.PublicId),
				roleVersion:    2, // yep, since setupFn will increment it to 2
				userIds:        []string{testUser.PublicId},
				groupIds:       []string{testGrp.PublicId},
				addToOrigUsers: false,
				addToOrigGrps:  false,
			},
			wantErr:          false,
			wantAffectedRows: 14,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var origUsers, origGrps []string
			if tt.setup != nil {
				origUsers, origGrps = tt.setup(tt.args.role)
			}
			if tt.args.addToOrigUsers {
				tt.args.userIds = append(tt.args.userIds, origUsers...)
			}
			if tt.args.addToOrigGrps {
				tt.args.groupIds = append(tt.args.groupIds, origGrps...)
			}
			origRole, _, _, _, err := repo.LookupRole(context.Background(), tt.args.role.PublicId)
			require.NoError(err)

			principalIds := append(tt.args.userIds, tt.args.groupIds...)
			got, affectedRows, err := repo.SetPrincipalRoles(context.Background(), tt.args.role.PublicId, tt.args.roleVersion, principalIds, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				t.Log(err)
				return
			}
			t.Log(err)
			require.NoError(err)
			assert.Equal(tt.wantAffectedRows, affectedRows)
			assert.Equal(len(tt.args.userIds)+len(tt.args.groupIds), len(got))
			var gotIds []string
			for _, r := range got {
				gotIds = append(gotIds, r.PrincipalId)
			}
			var wantIds []string
			wantIds = append(wantIds, tt.args.userIds...)
			wantIds = append(wantIds, tt.args.groupIds...)
			sort.Strings(wantIds)
			sort.Strings(gotIds)
			assert.Equal(wantIds, gotIds)

			r, _, _, _, err := repo.LookupRole(context.Background(), tt.args.role.PublicId)
			require.NoError(err)
			if !strings.Contains(tt.name, "no change") {
				assert.Equalf(tt.args.roleVersion+1, r.Version, "%s unexpected version: %d/%d", tt.name, tt.args.roleVersion+1, r.Version)
				assert.Equalf(origRole.Version, r.Version-1, "%s unexpected version: %d/%d", tt.name, origRole.Version, r.Version-1)
			}
			t.Logf("roleScope: %v and origVersion/newVersion: %d/%d", r.ScopeId, origRole.Version, r.Version)
		})
	}
}
