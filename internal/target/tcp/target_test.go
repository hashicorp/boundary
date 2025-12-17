// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
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
	ctx := context.Background()
	type args struct {
		projectId string
		opt       []target.Option
	}
	tests := []struct {
		name          string
		args          args
		want          target.Target
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name:      "empty-projectId",
			args:      args{},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid-proj-id",
			args: args{
				projectId: prj.PublicId,
				opt:       []target.Option{target.WithName("valid-proj-id")},
			},
			want: func() target.Target {
				t, _ := target.New(
					ctx,
					tcp.Subtype,
					prj.PublicId,
					target.WithName("valid-proj-id"),
					target.WithSessionMaxSeconds(uint32((8 * time.Hour).Seconds())),
					target.WithSessionConnectionLimit(-1),
				)
				return t
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := target.New(ctx, tcp.Subtype, tt.args.projectId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(ctx, globals.TcpTargetPrefix)
				require.NoError(err)
				require.NoError(got.SetPublicId(ctx, id))
				err = db.New(conn).Create(ctx, got)
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
	ctx := context.Background()

	tests := []struct {
		name            string
		target          target.Target
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			target:          tcp.TestTarget(ctx, t, conn, proj.PublicId, tcp.TestTargetName(t, proj.PublicId)),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			target: func() target.Target {
				tar, _ := target.New(ctx, tcp.Subtype, proj.PublicId)

				id, err := db.NewPublicId(ctx, globals.TcpTargetPrefix)
				require.NoError(t, err)
				require.NoError(t, tar.SetPublicId(ctx, id))
				tar.SetName(tcp.TestTargetName(t, proj.PublicId))
				return tar
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteTarget := tcp.NewTestTarget(ctx, "")
			require.NoError(deleteTarget.SetPublicId(ctx, tt.target.GetPublicId()))
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
			foundTarget := tcp.NewTestTarget(ctx, "")
			require.NoError(foundTarget.SetPublicId(ctx, tt.target.GetPublicId()))
			err = rw.LookupById(context.Background(), foundTarget)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestTarget_Update(t *testing.T) {
	t.Parallel()
	id := tcp.TestId(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		nullPaths      []string
		ProjectId      string
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
				ProjectId:      proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "proj-id-not-in-mask",
			args: args{
				name:           "proj-id" + id,
				fieldMaskPaths: []string{"Name"},
				ProjectId:      proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "empty-project-id",
			args: args{
				name:           "empty-project-id" + id,
				fieldMaskPaths: []string{"Name"},
				ProjectId:      "",
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ProjectId:      proj.PublicId,
			},
			wantErr:    true,
			wantDup:    true,
			wantErrMsg: `db.Update: duplicate key value violates unique constraint "target_tcp_project_id_name_uq": unique constraint violation: integrity violation: error #1002`,
		},
		{
			name: "set description null",
			args: args{
				name:           "set description null" + id,
				fieldMaskPaths: []string{"Name"},
				nullPaths:      []string{"Description"},
				ProjectId:      proj.PublicId,
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
				ProjectId:      proj.PublicId,
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
				ProjectId:      proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			if tt.wantDup {
				target := tcp.TestTarget(ctx, t, conn, proj.PublicId, tcp.TestTargetName(t, proj.PublicId))
				target.SetName(tt.args.name)
				_, err := rw.Update(ctx, target, tt.args.fieldMaskPaths, tt.args.nullPaths)
				require.NoError(err)
			}

			id := tcp.TestId(t)
			tar := tcp.TestTarget(ctx, t, conn, proj.PublicId, id, target.WithDescription(id))

			updateTarget := tcp.NewTestTarget(ctx, tt.args.ProjectId)
			require.NoError(updateTarget.SetPublicId(ctx, tar.GetPublicId()))
			updateTarget.SetName(tt.args.name)
			updateTarget.SetDescription(tt.args.description)

			updatedRows, err := rw.Update(ctx, updateTarget, tt.args.fieldMaskPaths, tt.args.nullPaths)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = db.TestVerifyOplog(t, rw, tar.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Contains(err.Error(), "record not found")
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(tar.GetUpdateTime(), updateTarget.GetUpdateTime())
			foundTarget := tcp.NewTestTarget(ctx, tt.args.ProjectId)
			require.NoError(foundTarget.SetPublicId(ctx, tar.GetPublicId()))
			err = rw.LookupByPublicId(ctx, foundTarget)
			require.NoError(err)
			assert.True(proto.Equal(updateTarget.(*tcp.Target).Target, foundTarget.(*tcp.Target).Target))
			if len(tt.args.nullPaths) != 0 {
				underlyingDB, err := conn.SqlDB(ctx)
				require.NoError(err)
				dbassert := dbassert.New(t, underlyingDB)
				for _, f := range tt.args.nullPaths {
					ft := foundTarget.(*tcp.Target)
					dbassert.IsNull(&ft, f)
				}
			}
		})
	}
	t.Run("update dup names in diff projects", func(t *testing.T) {
		ctx := context.Background()
		assert, require := assert.New(t), require.New(t)
		id := tcp.TestId(t)
		_, proj2 := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		_ = tcp.TestTarget(ctx, t, conn, proj2.PublicId, id, target.WithDescription(id))
		projTarget := tcp.TestTarget(ctx, t, conn, proj.PublicId, id)
		projTarget.SetName(id)
		updatedRows, err := rw.Update(ctx, projTarget, []string{"Name"}, nil)
		require.NoError(err)
		assert.Equal(1, updatedRows)

		foundTarget, _ := target.New(ctx, tcp.Subtype, proj2.PublicId)
		require.NoError(foundTarget.SetPublicId(ctx, projTarget.GetPublicId()))
		err = rw.LookupByPublicId(ctx, foundTarget)
		require.NoError(err)
		assert.Equal(id, projTarget.GetName())
	})
}

func TestTarget_Clone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		tar := tcp.TestTarget(ctx, t, conn, proj.PublicId, tcp.TestTargetName(t, proj.PublicId),
			target.WithAddress("8.8.8.8"),
		)
		cp := tar.Clone()
		assert.True(proto.Equal(cp.(*tcp.Target).Target, tar.(*tcp.Target).Target))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		_, proj2 := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		target1 := tcp.TestTarget(ctx, t, conn, proj.PublicId, tcp.TestTargetName(t, proj.PublicId))
		talias := tcp.TestTarget(ctx, t, conn, proj2.PublicId, tcp.TestTargetName(t, proj2.PublicId))

		cp := target1.Clone()
		assert.True(!proto.Equal(cp.(*tcp.Target).Target, talias.(*tcp.Target).Target))
	})
}

func TestTable_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := tcp.DefaultTableName
	ctx := context.Background()
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
			def, _ := target.New(ctx, tcp.Subtype, "testScope")
			require.Equal(defaultTableName, def.(*tcp.Target).TableName())
			ss, _ := target.New(ctx, tcp.Subtype, "testScope")
			s := ss.(*tcp.Target)
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}

func TestTarget_oplog(t *testing.T) {
	ctx := context.Background()
	id := tcp.TestId(t)
	tests := []struct {
		name   string
		target target.Target
		op     oplog.OpType
		want   oplog.Metadata
	}{
		{
			name: "simple",
			target: func() target.Target {
				tar, _ := target.New(ctx, tcp.Subtype, id)
				if err := tar.SetPublicId(ctx, id); err != nil {
					t.Fatalf("failed to set public id: %s", err)
				}
				return tar
			}(),
			op: oplog.OpType_OP_TYPE_CREATE,
			want: oplog.Metadata{
				"resource-public-id": []string{id},
				"resource-type":      []string{"tcp target"},
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"project-id":         []string{id},
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
