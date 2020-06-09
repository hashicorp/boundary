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
	"google.golang.org/protobuf/proto"
)

func TestNewGroup(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)
	id := testId(t)

	type args struct {
		organizationPublicId string
		opt                  []Option
	}
	tests := []struct {
		name            string
		args            args
		wantErr         bool
		wantErrMsg      string
		wantName        string
		wantDescription string
	}{
		{
			name: "valid",
			args: args{
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithName(id), WithDescription(id)},
			},
			wantErr:         false,
			wantName:        id,
			wantDescription: id,
		},
		{
			name: "valid-proj",
			args: args{
				organizationPublicId: proj.PublicId,
				opt:                  []Option{WithName(id), WithDescription(id)},
			},
			wantErr:         false,
			wantName:        id,
			wantDescription: id,
		},
		{
			name: "valid-with-no-options",
			args: args{
				organizationPublicId: org.PublicId,
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
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewGroup(tt.args.organizationPublicId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
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
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)
	t.Run("valid-with-org", func(t *testing.T) {
		id := testId(t)
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		grp, err := NewGroup(org.PublicId, WithName(id), WithDescription(id))
		require.NoError(err)
		grpId, err := newGroupId()
		require.NoError(err)
		grp.PublicId = grpId
		err = w.Create(context.Background(), grp)
		require.NoError(err)
		assert.NotEmpty(grp.PublicId)

		foundGrp := allocGroup()
		foundGrp.PublicId = grp.PublicId
		err = w.LookupByPublicId(context.Background(), &foundGrp)
		require.NoError(err)
		assert.Equal(grp, &foundGrp)
	})
	t.Run("valid-with-proj", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		id := testId(t)
		grp, err := NewGroup(proj.PublicId, WithName(id), WithDescription(id))
		require.NoError(err)
		grpId, err := newGroupId()
		require.NoError(err)
		grp.PublicId = grpId
		err = w.Create(context.Background(), grp)
		require.NoError(err)
		assert.NotEmpty(grp.PublicId)

		foundGrp := allocGroup()
		foundGrp.PublicId = grp.PublicId
		err = w.LookupByPublicId(context.Background(), &foundGrp)
		require.NoError(err)
		assert.Equal(grp, &foundGrp)
	})
	t.Run("bad-scope-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		id := testId(t)
		grp, err := NewGroup(id)
		require.NoError(err)
		grpId, err := newGroupId()
		require.NoError(err)
		grp.PublicId = grpId
		err = w.Create(context.Background(), grp)
		require.Error(err)
		assert.Equal("create: vet for write failed scope is not found", err.Error())
	})
}
func Test_GroupUpdate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	id := testId(t)
	org, proj := TestScopes(t, conn)
	rw := db.New(conn)
	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
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
			wantErrMsg: "update: vet for write failed not allowed to change a resource's scope",
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
			wantErrMsg: `update: failed pq: duplicate key value violates unique constraint "iam_group_name_scope_id_key"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				grp := TestGroup(t, conn, org.PublicId)
				grp.Name = tt.args.name
				_, err := rw.Update(context.Background(), grp, tt.args.fieldMaskPaths, nil)
				require.NoError(err)
			}

			grp := TestGroup(t, conn, org.PublicId)

			updateGrp := allocGroup()
			updateGrp.PublicId = grp.PublicId
			updateGrp.ScopeId = tt.args.ScopeId
			updateGrp.Name = tt.args.name
			updateGrp.Description = tt.args.description

			updatedRows, err := rw.Update(context.Background(), &updateGrp, tt.args.fieldMaskPaths, nil)
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
		})
	}
}

func Test_GroupDelete(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()

	rw := db.New(conn)
	id := testId(t)
	org, _ := TestScopes(t, conn)

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
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestGroup_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &Group{}
	ty := r.ResourceType()
	assert.Equal(ty, ResourceTypeGroup)
}

func TestGroup_GetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, proj := TestScopes(t, conn)

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
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, _ := TestScopes(t, conn)

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
