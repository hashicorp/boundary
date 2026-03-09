// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestNewUserRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	orgRole := TestRole(t, conn, org.PublicId)
	projRole := TestRole(t, conn, proj.PublicId)
	user := TestUser(t, repo, org.PublicId)

	type args struct {
		roleId string
		userId string
		opt    []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *UserRole
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "valid-org",
			args: args{
				roleId: orgRole.PublicId,
				userId: user.PublicId,
			},
			want: func() *UserRole {
				r := allocUserRole()
				r.RoleId = orgRole.PublicId
				r.PrincipalId = user.PublicId
				return &r
			}(),
		},
		{
			name: "valid-proj",
			args: args{
				roleId: projRole.PublicId,
				userId: user.PublicId,
			},
			want: func() *UserRole {
				r := allocUserRole()
				r.RoleId = projRole.PublicId
				r.PrincipalId = user.PublicId
				return &r
			}(),
		},
		{
			name: "empty-role-id",
			args: args{
				roleId: "",
				userId: user.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-user-id",
			args: args{
				roleId: orgRole.PublicId,
				userId: "",
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewUserRole(ctx, tt.args.roleId, tt.args.userId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestUserRole_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	org2, proj2 := TestScopes(t, repo)
	type args struct {
		role *UserRole
	}
	tests := []struct {
		name       string
		args       args
		wantDup    bool
		wantErr    bool
		wantErrMsg string
		wantIsErr  errors.Code
	}{
		{
			name: "valid-with-org",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, org.PublicId)
					principal := TestUser(t, repo, org.PublicId)
					principalRole, err := NewUserRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-proj",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, proj.PublicId)
					principal := TestUser(t, repo, org.PublicId)
					principalRole, err := NewUserRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr: false,
		},
		{
			name: "cross-org",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, org2.PublicId)
					principal := TestUser(t, repo, org.PublicId)
					principalRole, err := NewUserRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
		},
		{
			name: "cross-proj",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, proj2.PublicId)
					principal := TestUser(t, repo, org.PublicId)
					principalRole, err := NewUserRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
		},
		{
			name: "bad-role-id",
			args: args{
				role: func() *UserRole {
					id := testId(t)
					principal := TestUser(t, repo, org.PublicId)
					principalRole, err := NewUserRole(ctx, id, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr:    true,
			wantErrMsg: "integrity violation: error #1003",
		},
		{
			name: "bad-user-id",
			args: args{
				role: func() *UserRole {
					id := testId(t)
					role := TestRole(t, conn, proj.PublicId)
					principalRole, err := NewUserRole(ctx, role.PublicId, id)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr:    true,
			wantErrMsg: "integrity violation: error #1003",
		},
		{
			name: "missing-role-id",
			args: args{
				role: func() *UserRole {
					principal := TestUser(t, repo, org.PublicId)
					return &UserRole{
						UserRole: &store.UserRole{
							RoleId:      "",
							PrincipalId: principal.PublicId,
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "iam.(UserRole).VetForWrite: missing role id: parameter violation: error #100",
			wantIsErr:  errors.InvalidParameter,
		},
		{
			name: "missing-user-id",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, proj.PublicId)
					return &UserRole{
						UserRole: &store.UserRole{
							RoleId:      role.PublicId,
							PrincipalId: "",
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "iam.(UserRole).VetForWrite: missing user id: parameter violation: error #100",
			wantIsErr:  errors.InvalidParameter,
		},
		{
			name: "dup-at-org",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, org.PublicId)
					principal := TestUser(t, repo, org.PublicId)
					principalRole, err := NewUserRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `db.Create: duplicate key value violates unique constraint "iam_user_role_pkey": unique constraint violation`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := db.New(conn)
			if tt.wantDup {
				r := tt.args.role.Clone().(*UserRole)
				err := w.Create(context.Background(), r)
				require.NoError(err)
			}
			r := tt.args.role.Clone().(*UserRole)
			err := w.Create(context.Background(), r)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			assert.NoError(err)

			found := allocUserRole()
			err = w.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", []any{r.RoleId, r.PrincipalId})
			require.NoError(err)
			assert.Empty(cmp.Diff(r, &found, protocmp.Transform()))
		})
	}
}

func TestUserRole_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	rw := db.New(conn)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r := TestRole(t, conn, org.PublicId)
		u := TestUser(t, repo, org.PublicId)
		u2 := TestUser(t, repo, org.PublicId)
		userRole := TestUserRole(t, conn, r.PublicId, u.PublicId)
		updateRole := userRole.Clone().(*UserRole)
		updateRole.PrincipalId = u2.PublicId
		updatedRows, err := rw.Update(context.Background(), updateRole, []string{"PrincipalId"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestUserRole_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, repo)
	u := TestUser(t, repo, org.PublicId)
	r := TestRole(t, conn, org.PublicId)

	tests := []struct {
		name            string
		role            *UserRole
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			role:            TestUserRole(t, conn, r.PublicId, u.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			role:            func() *UserRole { r := allocUserRole(); r.PrincipalId = id; r.RoleId = id; return &r }(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteRole := allocUserRole()
			deleteRole.RoleId = tt.role.GetRoleId()
			deleteRole.PrincipalId = tt.role.GetPrincipalId()
			deletedRows, err := rw.Delete(context.Background(), &deleteRole)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found := allocUserRole()
			err = rw.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", []any{tt.role.GetRoleId(), tt.role.GetPrincipalId()})
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestUserRole_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	user := TestUser(t, repo, org.PublicId)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		role := TestRole(t, conn, org.PublicId)
		userRole := TestUserRole(t, conn, role.PublicId, user.PublicId)
		cp := userRole.Clone()
		assert.True(proto.Equal(cp.(*UserRole).UserRole, userRole.UserRole))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		role := TestRole(t, conn, org.PublicId)
		role2 := TestRole(t, conn, proj.PublicId)
		userRole := TestUserRole(t, conn, role.PublicId, user.PublicId)
		userRole2 := TestUserRole(t, conn, role2.PublicId, user.PublicId)
		cp := userRole.Clone()
		assert.True(!proto.Equal(cp.(*UserRole).UserRole, userRole2.UserRole))
	})
}

func TestNewGroupRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	orgRole := TestRole(t, conn, org.PublicId)
	projRole := TestRole(t, conn, proj.PublicId)
	group := TestGroup(t, conn, org.PublicId)

	type args struct {
		roleId  string
		groupId string
		opt     []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *GroupRole
		wantErr   bool
		wantIsErr errors.Code
	}{
		{
			name: "valid-org",
			args: args{
				roleId:  orgRole.PublicId,
				groupId: group.PublicId,
			},
			want: func() *GroupRole {
				r := allocGroupRole()
				r.RoleId = orgRole.PublicId
				r.PrincipalId = group.PublicId
				return &r
			}(),
		},
		{
			name: "valid-proj",
			args: args{
				roleId:  projRole.PublicId,
				groupId: group.PublicId,
			},
			want: func() *GroupRole {
				r := allocGroupRole()
				r.RoleId = projRole.PublicId
				r.PrincipalId = group.PublicId
				return &r
			}(),
		},
		{
			name: "empty-role-id",
			args: args{
				roleId:  "",
				groupId: group.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-group-id",
			args: args{
				roleId:  orgRole.PublicId,
				groupId: "",
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewGroupRole(ctx, tt.args.roleId, tt.args.groupId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestGroupRole_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	org2, proj2 := TestScopes(t, repo)
	type args struct {
		role *GroupRole
	}
	tests := []struct {
		name       string
		args       args
		wantDup    bool
		wantErr    bool
		wantErrMsg string
		wantIsErr  errors.Code
	}{
		{
			name: "valid-with-org",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, org.PublicId)
					principal := TestGroup(t, conn, org.PublicId)
					principalRole, err := NewGroupRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-proj",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, proj.PublicId)
					principal := TestGroup(t, conn, proj.PublicId)
					principalRole, err := NewGroupRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr: false,
		},
		{
			name: "cross-org",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, org2.PublicId)
					principal := TestGroup(t, conn, org.PublicId)
					principalRole, err := NewGroupRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
		},
		{
			name: "cross-proj",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, proj2.PublicId)
					principal := TestGroup(t, conn, org.PublicId)
					principalRole, err := NewGroupRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
		},
		{
			name: "bad-role-id",
			args: args{
				role: func() *GroupRole {
					id := testId(t)
					principal := TestGroup(t, conn, org.PublicId)
					principalRole, err := NewGroupRole(ctx, id, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr:    true,
			wantErrMsg: "integrity violation: error #1003",
		},
		{
			name: "bad-user-id",
			args: args{
				role: func() *GroupRole {
					id := testId(t)
					role := TestRole(t, conn, proj.PublicId)
					principalRole, err := NewGroupRole(ctx, role.PublicId, id)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantErr:    true,
			wantErrMsg: "integrity violation: error #1003",
		},
		{
			name: "missing-role-id",
			args: args{
				role: func() *GroupRole {
					principal := TestGroup(t, conn, org.PublicId)
					return &GroupRole{
						GroupRole: &store.GroupRole{
							RoleId:      "",
							PrincipalId: principal.PublicId,
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "parameter violation: error #100",
			wantIsErr:  errors.InvalidParameter,
		},
		{
			name: "missing-group-id",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, proj.PublicId)
					return &GroupRole{
						GroupRole: &store.GroupRole{
							RoleId:      role.PublicId,
							PrincipalId: "",
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "parameter violation: error #100",
			wantIsErr:  errors.InvalidParameter,
		},
		{
			name: "dup-at-org",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, org.PublicId)
					principal := TestGroup(t, conn, org.PublicId)
					principalRole, err := NewGroupRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `unique constraint violation: integrity violation: error #1002`,
		},
		{
			name: "dup-at-proj",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, proj.PublicId)
					principal := TestGroup(t, conn, proj.PublicId)
					principalRole, err := NewGroupRole(ctx, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `unique constraint violation: integrity violation: error #1002`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := db.New(conn)
			if tt.wantDup {
				r := tt.args.role.Clone().(*GroupRole)
				err := w.Create(context.Background(), r)
				require.NoError(err)
			}
			r := tt.args.role.Clone().(*GroupRole)
			err := w.Create(context.Background(), r)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			assert.NoError(err)

			found := allocGroupRole()
			err = w.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", []any{r.RoleId, r.PrincipalId})
			require.NoError(err)
			assert.Empty(cmp.Diff(r, &found, protocmp.Transform()))
		})
	}
}

func TestGroupRole_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	rw := db.New(conn)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r := TestRole(t, conn, org.PublicId)
		g := TestGroup(t, conn, org.PublicId)
		g2 := TestGroup(t, conn, org.PublicId)
		groupRole := TestGroupRole(t, conn, r.PublicId, g.PublicId)
		updateRole := groupRole.Clone().(*GroupRole)
		updateRole.PrincipalId = g2.PublicId
		updatedRows, err := rw.Update(context.Background(), updateRole, []string{"PrincipalId"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestGroupRole_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, repo)
	g := TestGroup(t, conn, org.PublicId)
	r := TestRole(t, conn, org.PublicId)

	tests := []struct {
		name            string
		role            *GroupRole
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			role:            TestGroupRole(t, conn, r.PublicId, g.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			role: func() *GroupRole {
				r := allocGroupRole()
				r.PrincipalId = id
				r.RoleId = id
				return &r
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteRole := allocGroupRole()
			deleteRole.RoleId = tt.role.GetRoleId()
			deleteRole.PrincipalId = tt.role.GetPrincipalId()
			deletedRows, err := rw.Delete(context.Background(), &deleteRole)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found := allocGroupRole()
			err = rw.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", []any{tt.role.GetRoleId(), tt.role.GetPrincipalId()})
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestGroupRole_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		grp := TestGroup(t, conn, org.PublicId)
		role := TestRole(t, conn, org.PublicId)
		grpRole := TestGroupRole(t, conn, role.PublicId, grp.PublicId)
		cp := grpRole.Clone()
		assert.True(proto.Equal(cp.(*GroupRole).GroupRole, grpRole.GroupRole))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		grp := TestGroup(t, conn, org.PublicId)
		grp2 := TestGroup(t, conn, proj.PublicId)
		role := TestRole(t, conn, org.PublicId)
		role2 := TestRole(t, conn, proj.PublicId)
		grpRole := TestGroupRole(t, conn, role.PublicId, grp.PublicId)
		grpRole2 := TestGroupRole(t, conn, role2.PublicId, grp2.PublicId)
		cp := grpRole.Clone()
		assert.True(!proto.Equal(cp.(*GroupRole).GroupRole, grpRole2.GroupRole))
	})
}

func TestPrincipalRole_SetTableName(t *testing.T) {
	defaultTableName := principalRoleViewDefaultTable
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := &PrincipalRole{
				PrincipalRoleView: &store.PrincipalRoleView{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &PrincipalRole{
				PrincipalRoleView: &store.PrincipalRoleView{},
				tableName:         tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestUserRole_SetTableName(t *testing.T) {
	defaultTableName := userRoleDefaultTable
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocUserRole()
			require.Equal(defaultTableName, def.TableName())
			s := &UserRole{
				UserRole:  &store.UserRole{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestGroupRole_SetTableName(t *testing.T) {
	defaultTableName := groupRoleDefaultTable
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocGroupRole()
			require.Equal(defaultTableName, def.TableName())
			s := &GroupRole{
				GroupRole: &store.GroupRole{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestManagedGroupRole_SetTableName(t *testing.T) {
	defaultTableName := managedGroupRoleDefaultTable
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocManagedGroupRole()
			require.Equal(defaultTableName, def.TableName())
			s := &ManagedGroupRole{
				ManagedGroupRole: &store.ManagedGroupRole{},
				tableName:        tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
