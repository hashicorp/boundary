package target

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// NOTE: there are no update tests since all the RootKey attributes are
// immutable and those tests are covered by TestRootKey_ImmutableFields

func TestTcpTarget_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	type args struct {
		scopeId string
		name    string
		opt     []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *TcpTarget
		wantErr       bool
		wantIsErr     error
		create        bool
		wantCreateErr bool
	}{
		{
			name:      "empty-scopeId",
			args:      args{},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-org-config",
			args: args{
				scopeId: org.PublicId,
				name:    "valid-org-config",
				opt:     []Option{WithDescription("valid-org-config-description"), WithDefaultPort(uint32(22))},
			},
			want: func() *TcpTarget {
				t := allocTcpTarget()
				t.ScopeId = org.PublicId
				t.Name = "valid-org-config"
				t.Description = "valid-org-config-description"
				t.DefaultPort = uint32(22)
				return &t
			}(),
			create: true,
		},
		{
			name: "valid-proj-scope",
			args: args{
				scopeId: prj.PublicId,
				name:    "valid-proj-scope",
			},
			want: func() *TcpTarget {
				t := allocTcpTarget()
				t.ScopeId = prj.PublicId
				t.Name = "valid-proj-scope"
				return &t
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
			got, err := NewTcpTarget(tt.args.scopeId, tt.args.name, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := newTcpId()
				require.NoError(err)
				got.PublicId = id
				err = db.New(conn).Create(context.Background(), got)
				if tt.wantCreateErr {
					assert.Error(err)
					return
				} else {
					assert.NoError(err)
				}
			}
		})
	}
}

func TestTcpTarget_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	tests := []struct {
		name            string
		target          *TcpTarget
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			target:          TestTcpTarget(t, conn, org.PublicId, testTargetName(t, org.PublicId)),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			target: func() *TcpTarget {
				target := allocTcpTarget()
				id, err := newTcpId()
				require.NoError(t, err)
				target.PublicId = id
				target.ScopeId = org.PublicId
				target.Name = testTargetName(t, org.PublicId)
				return &target
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteTarget := allocTcpTarget()
			deleteTarget.PublicId = tt.target.PublicId
			deletedRows, err := rw.Delete(context.Background(), &deleteTarget)
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
			foundTarget := allocTcpTarget()
			foundTarget.PublicId = tt.target.PublicId
			err = rw.LookupById(context.Background(), &foundTarget)
			require.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestTcpTarget_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		target := TestTcpTarget(t, conn, org.PublicId, testTargetName(t, org.PublicId))
		cp := target.Clone()
		assert.True(proto.Equal(cp.(*TcpTarget).TcpTarget, target.TcpTarget))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		target := TestTcpTarget(t, conn, org.PublicId, testTargetName(t, org.PublicId))
		target2 := TestTcpTarget(t, conn, org2.PublicId, testTargetName(t, org2.PublicId))

		cp := target.Clone()
		assert.True(!proto.Equal(cp.(*TcpTarget).TcpTarget, target2.TcpTarget))
	})
}

func TestTcpTable_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := DefaultTcpTableName
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
			def := allocTcpTarget()
			require.Equal(defaultTableName, def.TableName())
			s := allocTcpTarget()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
