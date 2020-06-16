package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserRole(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)
	orgRole := TestRole(t, conn, org.PublicId)
	projRole := TestRole(t, conn, proj.PublicId)
	user := TestUser(t, conn, org.PublicId)

	type args struct {
		roleId string
		userId string
		opt    []Option
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
				roleId: orgRole.PublicId,
				userId: user.PublicId,
			},
			want: func() PrincipalRole {
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
			want: func() PrincipalRole {
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
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-user-id",
			args: args{
				roleId: orgRole.PublicId,
				userId: "",
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewUserRole(tt.args.roleId, tt.args.userId, tt.args.opt...)
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

func Test_UserRoleCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)
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
					principalRole, err := NewUserRole(role.PublicId, principal.PublicId)
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
					principalRole, err := NewUserRole(role.PublicId, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*UserRole)
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-role-id",
			args: args{
				role: func() *UserRole {
					id := testId(t)
					principal := TestUser(t, conn, org.PublicId)
					principalRole, err := NewUserRole(id, principal.PublicId)
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
					principalRole, err := NewUserRole(role.PublicId, id)
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
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: vet for write failed new user role: missing user id invalid parameter",
			wantIsErr:  db.ErrInvalidParameter,
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
				assert.Contains(tt.wantErrMsg, err.Error())
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

func TestNewGroupRole(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)
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
		want      PrincipalRole
		wantErr   bool
		wantIsErr error
	}{
		{
			name: "valid-org",
			args: args{
				roleId:  orgRole.PublicId,
				groupId: group.PublicId,
			},
			want: func() PrincipalRole {
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
			want: func() PrincipalRole {
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
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-group-id",
			args: args{
				roleId:  orgRole.PublicId,
				groupId: "",
			},
			want:      nil,
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewGroupRole(tt.args.roleId, tt.args.groupId, tt.args.opt...)
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

func Test_GroupRoleCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
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
					principalRole, err := NewGroupRole(role.PublicId, principal.PublicId)
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
					principalRole, err := NewGroupRole(role.PublicId, principal.PublicId)
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
					principalRole, err := NewGroupRole(id, principal.PublicId)
					require.NoError(t, err)
					return principalRole.(*GroupRole)
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: failed pq: group and role do not belong to the same scope",
		},
		{
			name: "bad-user-id",
			args: args{
				role: func() *GroupRole {
					id := testId(t)
					role := TestRole(t, conn, proj.PublicId)
					principalRole, err := NewGroupRole(role.PublicId, id)
					require.NoError(t, err)
					return principalRole.(*GroupRole)
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: failed pq: group and role do not belong to the same scope",
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
			wantErrMsg: "create: vet for write failed new group role: missing role id invalid parameter",
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
						},
					}
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: vet for write failed new group role: missing user id invalid parameter",
			wantIsErr:  db.ErrInvalidParameter,
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
				assert.Contains(tt.wantErrMsg, err.Error())
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
