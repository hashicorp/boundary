// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package iam

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestNewRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	id := testId(t)

	type args struct {
		scopePublicId string
		opt           []Option
	}
	tests := []struct {
		name            string
		args            args
		wantErr         bool
		wantErrMsg      string
		wantIsErr       errors.Code
		wantName        string
		wantDescription string
	}{
		{
			name: "valid",
			args: args{
				scopePublicId: org.PublicId,
				opt:           []Option{WithName(id), WithDescription("description-" + id)},
			},
			wantErr:         false,
			wantName:        id,
			wantDescription: "description-" + id,
		},
		{
			name: "valid-proj",
			args: args{
				scopePublicId: proj.PublicId,
				opt:           []Option{WithName(id), WithDescription("description-" + id)},
			},
			wantErr:         false,
			wantName:        id,
			wantDescription: "description-" + id,
		},
		{
			name: "valid-with-no-options" + id,
			args: args{
				scopePublicId: org.PublicId,
			},
			wantErr: false,
		},
		{
			name: "no-scope",
			args: args{
				opt: []Option{WithName(id)},
			},
			wantErr:    true,
			wantErrMsg: "iam.NewRole: missing scope id: parameter violation: error #100",
			wantIsErr:  errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRole(ctx, tt.args.scopePublicId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantName, got.Name)
			assert.Equal(tt.wantDescription, got.Description)
			assert.Empty(got.PublicId)
		})
	}
}

func Test_RoleCreate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	type args struct {
		role *Role
	}
	tests := []struct {
		name        string
		args        args
		wantDup     bool
		wantErr     bool
		wantErrMsg  string
		wantIsError error
	}{
		{
			name: "valid-with-org",
			args: args{
				role: func() *Role {
					id := testId(t)
					role, err := NewRole(ctx, org.PublicId, WithName(id), WithDescription("description-"+id))
					require.NoError(t, err)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					role.PublicId = grpId
					return role
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-proj",
			args: args{
				role: func() *Role {
					id := testId(t)
					role, err := NewRole(ctx, proj.PublicId, WithName(id), WithDescription("description-"+id))
					require.NoError(t, err)
					grpId, err := newRoleId(ctx)
					require.NoError(t, err)
					role.PublicId = grpId
					return role
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-dup-null-names-and-descriptions",
			args: args{
				role: func() *Role {
					role, err := NewRole(ctx, org.PublicId)
					require.NoError(t, err)
					roleId, err := newRoleId(ctx)
					require.NoError(t, err)
					role.PublicId = roleId
					return role
				}(),
			},
			wantDup: true,
			wantErr: false,
		},
		{
			name: "bad-scope-id",
			args: args{
				role: func() *Role {
					id := testId(t)
					role, err := NewRole(ctx, id)
					require.NoError(t, err)
					roleId, err := newRoleId(ctx)
					require.NoError(t, err)
					role.PublicId = roleId
					return role
				}(),
			},
			wantErr:    true,
			wantErrMsg: "iam.validateScopeForWrite: scope is not found: search issue: error #1100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := db.New(conn)
			if tt.wantDup {
				r := tt.args.role.Clone().(*Role)
				roleId, err := newRoleId(ctx)
				require.NoError(err)
				r.PublicId = roleId
				err = w.Create(ctx, r)
				require.NoError(err)
			}
			r := tt.args.role.Clone().(*Role)
			err := w.Create(ctx, r)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				return
			}
			assert.NoError(err)
			assert.NotEmpty(tt.args.role.PublicId)

			foundGrp := allocRole()
			foundGrp.PublicId = tt.args.role.PublicId
			err = w.LookupByPublicId(ctx, &foundGrp)
			require.NoError(err)
			assert.Empty(cmp.Diff(r, &foundGrp, protocmp.Transform()))
		})
	}
}

func Test_RoleUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)
	org, proj := TestScopes(t, repo)
	org2, proj2 := TestScopes(t, repo)
	rw := db.New(conn)
	type args struct {
		name            string
		description     string
		fieldMaskPaths  []string
		nullPaths       []string
		scopeId         string
		grantScopeId    string
		scopeIdOverride string
		opts            []db.Option
	}
	tests := []struct {
		name           string
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantDup        bool
	}{
		{
			name: "valid",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				scopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "proj-scope-id",
			args: args{
				name:            "proj-scope-id" + id,
				fieldMaskPaths:  []string{"ScopeId"},
				scopeId:         proj.PublicId,
				scopeIdOverride: org.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "iam.validateScopeForWrite: not allowed to change a resource's scope: parameter violation: error #100",
		},
		{
			name: "proj-scope-id-not-in-mask",
			args: args{
				name:           "proj-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				scopeId:        proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "empty-scope-id",
			args: args{
				name:           "empty-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				scopeId:        "",
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				scopeId:        org.PublicId,
			},
			wantErr:    true,
			wantDup:    true,
			wantErrMsg: `db.Update: duplicate key value violates unique constraint "iam_role_name_scope_id_uq": unique constraint violation: integrity violation: error #1002`,
		},
		{
			name: "set description null",
			args: args{
				name:           "set description null" + id,
				fieldMaskPaths: []string{"Name"},
				nullPaths:      []string{"Description"},
				scopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "set name null",
			args: args{
				description:    "set description null" + id,
				fieldMaskPaths: []string{"Description"},
				nullPaths:      []string{"Name"},
				scopeId:        org.PublicId,
			},
			wantDup:        true,
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "set description null",
			args: args{
				name:           "set name null" + id,
				fieldMaskPaths: []string{"Name"},
				nullPaths:      []string{"Description"},
				scopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "set grant scope in project with same scope",
			args: args{
				name:           "set grant scope in project with same scope",
				fieldMaskPaths: []string{"Name", "GrantScopeId"},
				scopeId:        proj.PublicId,
				grantScopeId:   proj.PublicId,
			},
			wantRowsUpdate: 1,
		},
		{
			name: "set grant scope in org with same scope",
			args: args{
				name:           "set grant scope in org with same scope",
				fieldMaskPaths: []string{"Name", "GrantScopeId"},
				scopeId:        org2.PublicId,
				grantScopeId:   org2.PublicId,
			},
			wantRowsUpdate: 1,
		},
		{
			name: "set grant scope in project with different scope",
			args: args{
				name:           "set grant scope in project with different scope",
				fieldMaskPaths: []string{"GrantScopeId"},
				scopeId:        proj.PublicId,
				grantScopeId:   proj2.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "db.Update: invalid to set grant_scope_id to non-same scope_id when role scope type is project: integrity violation: error #1104",
		},
		{
			name: "set grant scope in org",
			args: args{
				name:           "set grant scope in org",
				fieldMaskPaths: []string{"Name", "GrantScopeId"},
				scopeId:        org2.PublicId,
				grantScopeId:   proj2.PublicId,
			},
			wantRowsUpdate: 1,
		},
		{
			name: "set grant scope in external project",
			args: args{
				name:           "set grant scope in external project",
				fieldMaskPaths: []string{"GrantScopeId"},
				scopeId:        org.PublicId,
				grantScopeId:   proj2.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "db.Update: grant_scope_id is not a child project of the role scope: integrity violation: error #1104",
		},
		{
			name: "set grant scope in global",
			args: args{
				name:           "set grant scope in global",
				fieldMaskPaths: []string{"GrantScopeId"},
				scopeId:        org.PublicId,
				grantScopeId:   "global",
			},
			wantErr:    true,
			wantErrMsg: "db.Update: grant_scope_id is not a child project of the role scope: integrity violation: error #1104",
		},
		{
			name: "set grant scope to parent",
			args: args{
				name:           "set grant scope to parent",
				fieldMaskPaths: []string{"GrantScopeId"},
				scopeId:        proj2.PublicId,
				grantScopeId:   org2.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "db.Update: invalid to set grant_scope_id to non-same scope_id when role scope type is project: integrity violation: error #1104",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				r := TestRole(t, conn, tt.args.scopeId, WithName(tt.args.name))
				_, err := rw.Update(context.Background(), r, tt.args.fieldMaskPaths, tt.args.nullPaths)
				require.NoError(err)
			}

			id := testId(t)
			scopeId := tt.args.scopeId
			if scopeId == "" {
				scopeId = org.PublicId
			}
			role := TestRole(t, conn, scopeId, WithDescription(id), WithName(id))

			updateRole := allocRole()
			updateRole.PublicId = role.PublicId
			updateRole.ScopeId = tt.args.scopeId
			if tt.args.scopeIdOverride != "" {
				updateRole.ScopeId = tt.args.scopeIdOverride
			}
			updateRole.Name = tt.args.name
			updateRole.Description = tt.args.description
			updateRole.GrantScopeId = tt.args.grantScopeId

			updatedRows, err := rw.Update(context.Background(), &updateRole, tt.args.fieldMaskPaths, tt.args.nullPaths, tt.args.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, updatedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, role.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Contains(err.Error(), "record not found")
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(role.UpdateTime, updateRole.UpdateTime)
			foundRole := allocRole()
			foundRole.PublicId = role.GetPublicId()
			err = rw.LookupByPublicId(context.Background(), &foundRole)
			require.NoError(err)
			if tt.args.grantScopeId == "" {
				updateRole.GrantScopeId = role.ScopeId
			}
			assert.True(proto.Equal(updateRole, foundRole))
			if len(tt.args.nullPaths) != 0 {
				underlyingDB, err := conn.SqlDB(ctx)
				require.NoError(err)
				dbassert := dbassert.New(t, underlyingDB)
				for _, f := range tt.args.nullPaths {
					dbassert.IsNull(&foundRole, f)
				}
			}
		})
	}
	t.Run("update dup names in diff scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)
		_ = TestRole(t, conn, org.PublicId, WithDescription(id), WithName(id))
		projRole := TestRole(t, conn, proj.PublicId, WithName(id))
		updatedRows, err := rw.Update(context.Background(), projRole, []string{"Name"}, nil)
		require.NoError(err)
		assert.Equal(1, updatedRows)

		foundRole := allocRole()
		foundRole.PublicId = projRole.GetPublicId()
		err = rw.LookupByPublicId(context.Background(), &foundRole)
		require.NoError(err)
		assert.Equal(id, projRole.Name)
	})
	t.Run("attempt scope id update", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		role := TestRole(t, conn, org.PublicId, WithDescription(id), WithName(id))
		updateRole := allocRole()
		updateRole.PublicId = role.PublicId
		updateRole.ScopeId = proj.PublicId
		updatedRows, err := rw.Update(context.Background(), &updateRole, []string{"ScopeId"}, nil, db.WithSkipVetForWrite(true))
		require.Error(err)
		assert.Equal(0, updatedRows)
		assert.Contains(err.Error(), "immutable column: iam_role.scope_id: integrity violation: error #1003")
	})
}

func Test_RoleDelete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, repo)

	tests := []struct {
		name            string
		role            *Role
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			role:            TestRole(t, conn, org.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			role:            func() *Role { r := allocRole(); r.PublicId = id; return &r }(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteRole := allocRole()
			deleteRole.PublicId = tt.role.GetPublicId()
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
			foundRole := allocRole()
			foundRole.PublicId = tt.role.GetPublicId()
			err = rw.LookupByPublicId(context.Background(), &foundRole)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestRole_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &Role{}
	a := r.Actions()
	assert.Equal(a[action.Create.String()], action.Create)
	assert.Equal(a[action.Update.String()], action.Update)
	assert.Equal(a[action.Read.String()], action.Read)
	assert.Equal(a[action.Delete.String()], action.Delete)
	assert.Equal(a[action.AddGrants.String()], action.AddGrants)
	assert.Equal(a[action.RemoveGrants.String()], action.RemoveGrants)
	assert.Equal(a[action.SetGrants.String()], action.SetGrants)
	assert.Equal(a[action.AddPrincipals.String()], action.AddPrincipals)
	assert.Equal(a[action.RemovePrincipals.String()], action.RemovePrincipals)
	assert.Equal(a[action.SetPrincipals.String()], action.SetPrincipals)
}

func TestRole_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &Role{}
	ty := r.ResourceType()
	assert.Equal(ty, resource.Role)
}

func TestRole_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)

	t.Run("valid-org", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		role := TestRole(t, conn, org.PublicId)
		scope, err := role.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(org, scope))
	})
	t.Run("valid-proj", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		role := TestRole(t, conn, proj.PublicId)
		scope, err := role.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(proj, scope))
	})
}

func TestRole_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		role := TestRole(t, conn, org.PublicId, WithDescription("this is a test role"))
		cp := role.Clone()
		assert.True(proto.Equal(cp.(*Role).Role, role.Role))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		role := TestRole(t, conn, org.PublicId)
		role2 := TestRole(t, conn, org.PublicId)
		cp := role.Clone()
		assert.True(!proto.Equal(cp.(*Role).Role, role2.Role))
	})
}

func TestRole_SetTableName(t *testing.T) {
	defaultTableName := defaultRoleTableName
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
			def := allocRole()
			require.Equal(defaultTableName, def.TableName())
			s := &Role{
				Role:      &store.Role{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
