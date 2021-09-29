package tcp_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestTarget_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	type args struct {
		scopeId string
		opt     []target.Option
	}
	tests := []struct {
		name          string
		args          args
		want          *tcp.Target
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name:      "empty-scopeId",
			args:      args{},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid-proj-scope",
			args: args{
				scopeId: prj.PublicId,
				opt:     []target.Option{target.WithName("valid-proj-scope")},
			},
			want: func() *tcp.Target {
				t, _ := tcp.New(
					prj.PublicId,
					target.WithName("valid-proj-scope"),
					target.WithSessionMaxSeconds(uint32((8 * time.Hour).Seconds())),
					target.WithSessionConnectionLimit(1),
				)
				return t
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tcp.New(tt.args.scopeId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(tcp.TargetPrefix)
				require.NoError(err)
				got.PublicId = id
				err = db.New(conn).Create(context.Background(), got)
				if tt.wantCreateErr {
					assert.Error(err)
					return
				}

				assert.NoError(err)
			}
		})
	}
}

func TestTarget_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	tests := []struct {
		name            string
		target          *tcp.Target
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			target:          tcp.TestTarget(t, conn, proj.PublicId, tcp.TestTargetName(t, proj.PublicId)),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			target: func() *tcp.Target {
				tar, _ := tcp.New(proj.PublicId)

				id, err := db.NewPublicId(tcp.TargetPrefix)
				require.NoError(t, err)
				tar.PublicId = id
				tar.Name = tcp.TestTargetName(t, proj.PublicId)
				return tar
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteTarget := tcp.NewTestTarget("")
			deleteTarget.PublicId = tt.target.PublicId
			deletedRows, err := rw.Delete(context.Background(), deleteTarget)
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
			foundTarget := tcp.NewTestTarget("")
			foundTarget.PublicId = tt.target.PublicId
			err = rw.LookupById(context.Background(), foundTarget)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestTarget_Update(t *testing.T) {
	t.Parallel()
	id := tcp.TestId(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

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
				ScopeId:        proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
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
				ScopeId:        proj.PublicId,
			},
			wantErr:    true,
			wantDup:    true,
			wantErrMsg: `db.Update: duplicate key value violates unique constraint "target_tcp_scope_id_name_key": unique constraint violation: integrity violation: error #1002`,
		},
		{
			name: "set description null",
			args: args{
				name:           "set description null" + id,
				fieldMaskPaths: []string{"Name"},
				nullPaths:      []string{"Description"},
				ScopeId:        proj.PublicId,
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
				ScopeId:        proj.PublicId,
			},
			wantErr:    true,
			wantErrMsg: `db.Update: name must not be empty: not null constraint violated: integrity violation: error #1001`,
		},
		{
			name: "set description null",
			args: args{
				name:           "set name null" + id,
				fieldMaskPaths: []string{"Name"},
				nullPaths:      []string{"Description"},
				ScopeId:        proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				target := tcp.TestTarget(t, conn, proj.PublicId, tcp.TestTargetName(t, proj.PublicId))
				target.Name = tt.args.name
				_, err := rw.Update(context.Background(), target, tt.args.fieldMaskPaths, tt.args.nullPaths)
				require.NoError(err)
			}

			id := tcp.TestId(t)
			tar := tcp.TestTarget(t, conn, proj.PublicId, id, target.WithDescription(id))

			updateTarget := tcp.NewTestTarget(tt.args.ScopeId)
			updateTarget.PublicId = tar.PublicId
			updateTarget.Name = tt.args.name
			updateTarget.Description = tt.args.description

			updatedRows, err := rw.Update(context.Background(), updateTarget, tt.args.fieldMaskPaths, tt.args.nullPaths)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(t, rw, tar.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Contains(err.Error(), "record not found")
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(tar.UpdateTime, updateTarget.UpdateTime)
			foundTarget := tcp.NewTestTarget(tt.args.ScopeId)
			foundTarget.PublicId = tar.GetPublicId()
			err = rw.LookupByPublicId(context.Background(), foundTarget)
			require.NoError(err)
			assert.True(proto.Equal(updateTarget, foundTarget))
			if len(tt.args.nullPaths) != 0 {
				underlyingDB, err := conn.SqlDB(ctx)
				require.NoError(err)
				dbassert := dbassert.New(t, underlyingDB)
				for _, f := range tt.args.nullPaths {
					dbassert.IsNull(&foundTarget, f)
				}
			}
		})
	}
	t.Run("update dup names in diff scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := tcp.TestId(t)
		_, proj2 := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		_ = tcp.TestTarget(t, conn, proj2.PublicId, id, target.WithDescription(id))
		projTarget := tcp.TestTarget(t, conn, proj.PublicId, id)
		projTarget.Name = id
		updatedRows, err := rw.Update(context.Background(), projTarget, []string{"Name"}, nil)
		require.NoError(err)
		assert.Equal(1, updatedRows)

		foundTarget, _ := tcp.New(proj2.PublicId)
		foundTarget.PublicId = projTarget.GetPublicId()
		err = rw.LookupByPublicId(context.Background(), foundTarget)
		require.NoError(err)
		assert.Equal(id, projTarget.Name)
	})
}

func TestTarget_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		tar := tcp.TestTarget(t, conn, proj.PublicId, tcp.TestTargetName(t, proj.PublicId))
		cp := tar.Clone()
		assert.True(proto.Equal(cp.(*tcp.Target).Target, tar.Target))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		_, proj2 := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		target1 := tcp.TestTarget(t, conn, proj.PublicId, tcp.TestTargetName(t, proj.PublicId))
		target2 := tcp.TestTarget(t, conn, proj2.PublicId, tcp.TestTargetName(t, proj2.PublicId))

		cp := target1.Clone()
		assert.True(!proto.Equal(cp.(*tcp.Target).Target, target2.Target))
	})
}

func TestTable_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := tcp.DefaultTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def, _ := tcp.New("testScope")
			require.Equal(defaultTableName, def.TableName())
			s, _ := tcp.New("testScope")
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestTarget_oplog(t *testing.T) {
	id := tcp.TestId(t)
	tests := []struct {
		name   string
		target *tcp.Target
		op     oplog.OpType
		want   oplog.Metadata
	}{
		{
			name: "simple",
			target: func() *tcp.Target {
				t, _ := tcp.New(id)
				t.PublicId = id
				return t
			}(),
			op: oplog.OpType_OP_TYPE_CREATE,
			want: oplog.Metadata{
				"resource-public-id": []string{id},
				"resource-type":      []string{"tcp target"},
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{id},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.target.Oplog(tt.op)
			assert.Equal(got, tt.want)
		})
	}
}
