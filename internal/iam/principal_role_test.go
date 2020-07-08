package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewUserRole(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, proj := TestScopes(t, conn)
	orgRole := TestRole(t, conn, org.PublicId)
	projRole := TestRole(t, conn, proj.PublicId)
	user := TestUser(t, conn, org.PublicId)

	type args struct {
		roleId  string
		userId  string
		scopeId string
		opt     []Option
	}
	tests := []struct {
		name      string
		args      args
		want      PrincipalRole
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid-org",
			args: args{
				roleId:  orgRole.PublicId,
				userId:  user.PublicId,
				scopeId: org.PublicId,
			},
			want: func() PrincipalRole {
				r := allocUserRole()
				r.RoleId = orgRole.PublicId
				r.PrincipalId = user.PublicId
				r.ScopeId = org.PublicId
				return &r
			}(),
		},
		{
			name: "valid-proj",
			args: args{
				roleId:  projRole.PublicId,
				userId:  user.PublicId,
				scopeId: proj.PublicId,
			},
			want: func() PrincipalRole {
				r := allocUserRole()
				r.RoleId = projRole.PublicId
				r.PrincipalId = user.PublicId
				r.ScopeId = proj.PublicId
				return &r
			}(),
		},
		{
			name: "empty-role-id",
			args: args{
				roleId:  "",
				userId:  user.PublicId,
				scopeId: org.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-user-id",
			args: args{
				roleId:  orgRole.PublicId,
				userId:  "",
				scopeId: org.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewUserRole(tt.args.scopeId, tt.args.roleId, tt.args.userId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestUserRole_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, proj := TestScopes(t, conn)
	org2, proj2 := TestScopes(t, conn)
	type args struct {
		role *UserRole
	}
	tests := []struct {
		name       string
		args       args
		wantDup    bool
		wantErr    bool
		wantErrMsg string
		wantIsErr  error
	}{
		{
			name: "valid-with-org",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, org.PublicId)
					principal := TestUser(t, conn, org.PublicId)
					principalRole, err := NewUserRole(org.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*UserRole)
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-proj",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, proj.PublicId)
					principal := TestUser(t, conn, org.PublicId)
					principalRole, err := NewUserRole(proj.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*UserRole)
				}(),
			},
			wantErr: false,
		},
		{
			name: "invalid-org",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, org2.PublicId)
					principal := TestUser(t, conn, org.PublicId)
					principalRole, err := NewUserRole(org.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*UserRole)
				}(),
			},
			wantErr: true,
		},
		{
			name: "invalid-proj",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, proj2.PublicId)
					principal := TestUser(t, conn, org.PublicId)
					principalRole, err := NewUserRole(proj.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*UserRole)
				}(),
			},
			wantErr: true,
		},
		{
			name: "bad-role-id",
			args: args{
				role: func() *UserRole {
					id := testId(t)
					principal := TestUser(t, conn, org.PublicId)
					principalRole, err := NewUserRole(org.PublicId, id, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*UserRole)
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: failed pq: user and role do not belong to the same organization",
		},
		{
			name: "bad-user-id",
			args: args{
				role: func() *UserRole {
					id := testId(t)
					role := TestRole(t, conn, proj.PublicId)
					principalRole, err := NewUserRole(proj.PublicId, role.PublicId, id)
					require.NoError(t, err)
					return principalRole.(*UserRole)
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: failed pq: user and role do not belong to the same organization",
		},
		{
			name: "missing-role-id",
			args: args{
				role: func() *UserRole {
					principal := TestUser(t, conn, org.PublicId)
					return &UserRole{
						UserRole: &store.UserRole{
							RoleId:      "",
							PrincipalId: principal.PublicId,
							ScopeId:     org.PublicId,
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: vet for write failed new user role: missing role id invalid parameter",
			wantIsErr:  db.ErrInvalidParameter,
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
							ScopeId:     org.PublicId,
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: vet for write failed new user role: missing user id invalid parameter",
			wantIsErr:  db.ErrInvalidParameter,
		},
		{
			name: "dup-at-org",
			args: args{
				role: func() *UserRole {
					role := TestRole(t, conn, org.PublicId)
					principal := TestUser(t, conn, org.PublicId)
					principalRole, err := NewUserRole(org.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*UserRole)
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `create: failed pq: duplicate key value violates unique constraint "iam_user_role_pkey"`,
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
				if tt.wantIsErr != nil {
					assert.True(errors.Is(err, tt.wantIsErr))
				}
				return
			}
			assert.NoError(err)

			found := allocUserRole()
			err = w.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", r.RoleId, r.PrincipalId)
			require.NoError(err)
			assert.Equal(r, &found)
		})
	}
}

func TestUserRole_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	rw := db.New(conn)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r := TestRole(t, conn, org.PublicId)
		u := TestUser(t, conn, org.PublicId)
		u2 := TestUser(t, conn, org.PublicId)
		userRole := TestUserRole(t, conn, org.PublicId, r.PublicId, u.PublicId)
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
	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, conn)
	u := TestUser(t, conn, org.PublicId)
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
			role:            TestUserRole(t, conn, org.PublicId, r.PublicId, u.PublicId),
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
			err = rw.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", tt.role.GetRoleId(), tt.role.GetPrincipalId())
			require.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestUserRole_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, proj := TestScopes(t, conn)
	user := TestUser(t, conn, org.PublicId)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		role := TestRole(t, conn, org.PublicId)
		userRole := TestUserRole(t, conn, org.PublicId, role.PublicId, user.PublicId)
		cp := userRole.Clone()
		assert.True(proto.Equal(cp.(*UserRole).UserRole, userRole.UserRole))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		role := TestRole(t, conn, org.PublicId)
		role2 := TestRole(t, conn, proj.PublicId)
		userRole := TestUserRole(t, conn, org.PublicId, role.PublicId, user.PublicId)
		userRole2 := TestUserRole(t, conn, proj.PublicId, role2.PublicId, user.PublicId)
		cp := userRole.Clone()
		assert.True(!proto.Equal(cp.(*UserRole).UserRole, userRole2.UserRole))
	})
}

func TestUserRole_GetType(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	r := &UserRole{}
	ty := r.GetType()
	assert.Equal("user", ty)
}

func TestNewGroupRole(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, proj := TestScopes(t, conn)
	orgRole := TestRole(t, conn, org.PublicId)
	projRole := TestRole(t, conn, proj.PublicId)
	group := TestGroup(t, conn, org.PublicId)

	type args struct {
		roleId  string
		groupId string
		scopeId string
		opt     []Option
	}
	tests := []struct {
		name      string
		args      args
		want      PrincipalRole
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid-org",
			args: args{
				roleId:  orgRole.PublicId,
				groupId: group.PublicId,
				scopeId: org.PublicId,
			},
			want: func() PrincipalRole {
				r := allocGroupRole()
				r.RoleId = orgRole.PublicId
				r.PrincipalId = group.PublicId
				r.ScopeId = org.PublicId
				return &r
			}(),
		},
		{
			name: "valid-proj",
			args: args{
				roleId:  projRole.PublicId,
				groupId: group.PublicId,
				scopeId: proj.PublicId,
			},
			want: func() PrincipalRole {
				r := allocGroupRole()
				r.RoleId = projRole.PublicId
				r.PrincipalId = group.PublicId
				r.ScopeId = proj.PublicId
				return &r
			}(),
		},
		{
			name: "empty-role-id",
			args: args{
				roleId:  "",
				groupId: group.PublicId,
				scopeId: org.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-group-id",
			args: args{
				roleId:  orgRole.PublicId,
				groupId: "",
				scopeId: org.PublicId,
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewGroupRole(tt.args.scopeId, tt.args.roleId, tt.args.groupId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestGroupRole_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, proj := TestScopes(t, conn)
	type args struct {
		role *GroupRole
	}
	tests := []struct {
		name       string
		args       args
		wantDup    bool
		wantErr    bool
		wantErrMsg string
		wantIsErr  error
	}{
		{
			name: "valid-with-org",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, org.PublicId)
					principal := TestGroup(t, conn, org.PublicId)
					principalRole, err := NewGroupRole(org.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*GroupRole)
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
					principalRole, err := NewGroupRole(proj.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*GroupRole)
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-role-id",
			args: args{
				role: func() *GroupRole {
					id := testId(t)
					principal := TestGroup(t, conn, org.PublicId)
					principalRole, err := NewGroupRole(org.PublicId, id, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*GroupRole)
				}(),
			},
			wantErr:    true,
			wantErrMsg: `create: failed: pq: insert or update on table "iam_group_role" violates foreign key constraint "iam_group_role_scope_id_role_id_fkey"`,
		},
		{
			name: "bad-user-id",
			args: args{
				role: func() *GroupRole {
					id := testId(t)
					role := TestRole(t, conn, proj.PublicId)
					principalRole, err := NewGroupRole(org.PublicId, role.PublicId, id)
					require.NoError(t, err)
					return principalRole.(*GroupRole)
				}(),
			},
			wantErr:    true,
			wantErrMsg: `create: failed: pq: insert or update on table "iam_group_role" violates foreign key constraint "iam_group_role_scope_id_role_id_fkey"`,
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
							ScopeId:     org.PublicId,
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: vet for write failed: new group role: missing role id invalid parameter",
			wantIsErr:  db.ErrInvalidParameter,
		},
		{
			name: "missing-user-id",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, proj.PublicId)
					return &GroupRole{
						GroupRole: &store.GroupRole{
							RoleId:      role.PublicId,
							PrincipalId: "",
							ScopeId:     proj.PublicId,
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: vet for write failed: new group role: missing user id invalid parameter",
			wantIsErr:  db.ErrInvalidParameter,
		},
		{
			name: "dup-at-org",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, org.PublicId)
					principal := TestGroup(t, conn, org.PublicId)
					principalRole, err := NewGroupRole(org.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*GroupRole)
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `create: failed: pq: duplicate key value violates unique constraint`,
		},
		{
			name: "dup-at-proj",
			args: args{
				role: func() *GroupRole {
					role := TestRole(t, conn, proj.PublicId)
					principal := TestGroup(t, conn, proj.PublicId)
					principalRole, err := NewGroupRole(proj.PublicId, role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*GroupRole)
				}(),
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: `create: failed: pq: duplicate key value violates unique constraint`,
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
				if tt.wantIsErr != nil {
					assert.True(errors.Is(err, tt.wantIsErr))
				}
				return
			}
			assert.NoError(err)

			found := allocGroupRole()
			err = w.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", r.RoleId, r.PrincipalId)
			require.NoError(err)
			assert.Equal(r, &found)
		})
	}
}

func TestGroupRole_Update(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	rw := db.New(conn)

	t.Run("updates not allowed", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		r := TestRole(t, conn, org.PublicId)
		g := TestGroup(t, conn, org.PublicId)
		g2 := TestGroup(t, conn, org.PublicId)
		userRole := TestGroupRole(t, conn, org.PublicId, r.PublicId, g.PublicId)
		updateRole := userRole.Clone().(*GroupRole)
		updateRole.PrincipalId = g2.PublicId
		updatedRows, err := rw.Update(context.Background(), updateRole, []string{"PrincipalId"}, nil)
		require.Error(err)
		assert.Equal(0, updatedRows)
	})
}

func TestGroupRole_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, conn)
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
			role:            TestGroupRole(t, conn, org.PublicId, r.PublicId, g.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			role:            func() *GroupRole { r := allocGroupRole(); r.PrincipalId = id; r.RoleId = id; r.ScopeId = id; return &r }(),
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
			err = rw.LookupWhere(context.Background(), &found, "role_id = ? and principal_id = ?", tt.role.GetRoleId(), tt.role.GetPrincipalId())
			require.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestGroupRole_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, proj := TestScopes(t, conn)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		grp := TestGroup(t, conn, org.PublicId)
		role := TestRole(t, conn, org.PublicId)
		grpRole := TestGroupRole(t, conn, org.PublicId, role.PublicId, grp.PublicId)
		cp := grpRole.Clone()
		assert.True(proto.Equal(cp.(*GroupRole).GroupRole, grpRole.GroupRole))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		grp := TestGroup(t, conn, org.PublicId)
		grp2 := TestGroup(t, conn, proj.PublicId)
		role := TestRole(t, conn, org.PublicId)
		role2 := TestRole(t, conn, proj.PublicId)
		grpRole := TestGroupRole(t, conn, org.PublicId, role.PublicId, grp.PublicId)
		grpRole2 := TestGroupRole(t, conn, proj.PublicId, role2.PublicId, grp2.PublicId)
		cp := grpRole.Clone()
		assert.True(!proto.Equal(cp.(*GroupRole).GroupRole, grpRole2.GroupRole))
	})
}

func TestGroupRole_GetType(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	r := &GroupRole{}
	ty := r.GetType()
	assert.Equal("group", ty)
}
