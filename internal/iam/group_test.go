package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewGroup(t *testing.T) {
	t.Parallel()
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
		wantIsErr       error
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
			wantErrMsg: "new group: missing scope id invalid parameter",
			wantIsErr:  db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewGroup(tt.args.scopePublicId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
				if tt.wantIsErr != nil {
					assert.True(errors.Is(err, tt.wantIsErr))
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantName, got.Name)
			assert.Equal(tt.wantDescription, got.Description)
			assert.Empty(got.PublicId)
		})
	}
}

func Test_GroupCreate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)
	type args struct {
		group *Group
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
				group: func() *Group {
					id := testId(t)
					grp, err := NewGroup(org.PublicId, WithName(id), WithDescription("description-"+id))
					require.NoError(t, err)
					grpId, err := newGroupId()
					require.NoError(t, err)
					grp.PublicId = grpId
					return grp
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-proj",
			args: args{
				group: func() *Group {
					id := testId(t)
					grp, err := NewGroup(proj.PublicId, WithName(id), WithDescription("description-"+id))
					require.NoError(t, err)
					grpId, err := newGroupId()
					require.NoError(t, err)
					grp.PublicId = grpId
					return grp
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid-with-dup-null-names-and-descriptions",
			args: args{
				group: func() *Group {
					grp, err := NewGroup(org.PublicId)
					require.NoError(t, err)
					grpId, err := newGroupId()
					require.NoError(t, err)
					grp.PublicId = grpId
					return grp
				}(),
			},
			wantDup: true,
			wantErr: false,
		},
		{
			name: "bad-scope-id",
			args: args{
				group: func() *Group {
					id := testId(t)
					grp, err := NewGroup(id)
					require.NoError(t, err)
					grpId, err := newGroupId()
					require.NoError(t, err)
					grp.PublicId = grpId
					return grp
				}(),
			},
			wantErr:    true,
			wantErrMsg: "create: vet for write failed: scope is not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := db.New(conn)
			if tt.wantDup {
				g := tt.args.group.Clone().(*Group)
				grpId, err := newGroupId()
				require.NoError(err)
				g.PublicId = grpId
				err = w.Create(context.Background(), g)
				require.NoError(err)
			}
			g := tt.args.group.Clone().(*Group)
			err := w.Create(context.Background(), g)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.NotEmpty(tt.args.group.PublicId)

			foundGrp := allocGroup()
			foundGrp.PublicId = tt.args.group.PublicId
			err = w.LookupByPublicId(context.Background(), &foundGrp)
			require.NoError(err)
			assert.Equal(g, &foundGrp)
		})
	}
}

func Test_GroupUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)
	org, proj := TestScopes(t, repo)
	rw := db.New(conn)
	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		nullPaths      []string
		ScopeId        string
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
				ScopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "proj-scope-id",
			args: args{
				name:           "proj-scope-id" + id,
				fieldMaskPaths: []string{"ScopeId"},
				ScopeId:        proj.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "update: vet for write failed: not allowed to change a resource's scope",
		},
		{
			name: "proj-scope-id-not-in-mask",
			args: args{
				name:           "proj-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "empty-scope-id",
			args: args{
				name:           "empty-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        "",
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			wantErr:    true,
			wantDup:    true,
			wantErrMsg: `update: failed: pq: duplicate key value violates unique constraint "iam_group_name_scope_id_key"`,
		},
		{
			name: "set description null",
			args: args{
				name:           "set description null" + id,
				fieldMaskPaths: []string{"Name"},
				nullPaths:      []string{"Description"},
				ScopeId:        org.PublicId,
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
				ScopeId:        org.PublicId,
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
				ScopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				grp := TestGroup(t, conn, org.PublicId)
				grp.Name = tt.args.name
				_, err := rw.Update(context.Background(), grp, tt.args.fieldMaskPaths, tt.args.nullPaths)
				require.NoError(err)
			}

			id := testId(t)
			grp := TestGroup(t, conn, org.PublicId, WithDescription(id), WithName(id))

			updateGrp := allocGroup()
			updateGrp.PublicId = grp.PublicId
			updateGrp.ScopeId = tt.args.ScopeId
			updateGrp.Name = tt.args.name
			updateGrp.Description = tt.args.description

			updatedRows, err := rw.Update(context.Background(), &updateGrp, tt.args.fieldMaskPaths, tt.args.nullPaths)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(t, rw, grp.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(grp.UpdateTime, updateGrp.UpdateTime)
			foundGrp := allocGroup()
			foundGrp.PublicId = grp.GetPublicId()
			err = rw.LookupByPublicId(context.Background(), &foundGrp)
			require.NoError(err)
			assert.True(proto.Equal(updateGrp, foundGrp))
			if len(tt.args.nullPaths) != 0 {
				dbassert := dbassert.New(t, conn.DB())
				for _, f := range tt.args.nullPaths {
					dbassert.IsNull(&foundGrp, f)
				}
			}
		})
	}
	t.Run("update dup names in diff scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)
		_ = TestGroup(t, conn, org.PublicId, WithDescription(id), WithName(id))
		projGrp := TestGroup(t, conn, proj.PublicId)
		projGrp.Name = id
		updatedRows, err := rw.Update(context.Background(), projGrp, []string{"Name"}, nil)
		require.NoError(err)
		assert.Equal(1, updatedRows)

		foundGrp := allocGroup()
		foundGrp.PublicId = projGrp.GetPublicId()
		err = rw.LookupByPublicId(context.Background(), &foundGrp)
		require.NoError(err)
		assert.Equal(id, projGrp.Name)
	})
}

func Test_GroupDelete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, repo)

	tests := []struct {
		name            string
		group           *Group
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			group:           TestGroup(t, conn, org.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			group:           func() *Group { g := allocGroup(); g.PublicId = id; return &g }(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteGroup := allocGroup()
			deleteGroup.PublicId = tt.group.GetPublicId()
			deletedRows, err := rw.Delete(context.Background(), &deleteGroup)
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
			foundGrp := allocGroup()
			foundGrp.PublicId = tt.group.GetPublicId()
			err = rw.LookupByPublicId(context.Background(), &foundGrp)
			require.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestGroup_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &Group{}
	a := r.Actions()
	assert.Equal(a[action.Create.String()], action.Create)
	assert.Equal(a[action.Update.String()], action.Update)
	assert.Equal(a[action.Read.String()], action.Read)
	assert.Equal(a[action.Delete.String()], action.Delete)
}

func TestGroup_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &Group{}
	ty := r.ResourceType()
	assert.Equal(ty, resource.Group)
}

func TestGroup_GetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, proj := TestScopes(t, repo)

	t.Run("valid-org", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		grp := TestGroup(t, conn, org.PublicId)
		scope, err := grp.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(org, scope))
	})
	t.Run("valid-proj", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		grp := TestGroup(t, conn, proj.PublicId)
		scope, err := grp.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(proj, scope))
	})
}

func TestGroup_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		grp := TestGroup(t, conn, org.PublicId)
		cp := grp.Clone()
		assert.True(proto.Equal(cp.(*Group).Group, grp.Group))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		grp := TestGroup(t, conn, org.PublicId)
		grp2 := TestGroup(t, conn, org.PublicId)

		cp := grp.Clone()
		assert.True(!proto.Equal(cp.(*Group).Group, grp2.Group))
	})
}

func TestGroup_SetTableName(t *testing.T) {
	defaultTableName := defaultGroupTableName
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
			def := allocGroup()
			require.Equal(defaultTableName, def.TableName())
			s := &Group{
				Group:     &store.Group{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
