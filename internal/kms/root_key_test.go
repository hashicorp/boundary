package kms

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// NOTE: there are no update tests since all the RootKey attributes are
// immutable and those tests are covered by TestRootKey_ImmutableFields

func TestRootKey_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, proj := iam.TestScopes(t, conn)
	type args struct {
		scopeId string
		opt     []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *RootKey
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
			},
			want: func() *RootKey {
				k := allocRootKey()
				k.ScopeId = org.PublicId
				return &k
			}(),
			create: true,
		},
		{
			name: "valid-global-config",
			args: args{
				scopeId: "global",
			},
			want: func() *RootKey {
				k := allocRootKey()
				k.ScopeId = "global"
				return &k
			}(),
			create: true,
		},
		{
			// root keys are not valid at the project scope level.
			name: "invalid-project-config",
			args: args{
				scopeId: proj.PublicId,
			},
			want: func() *RootKey {
				k := allocRootKey()
				k.ScopeId = proj.PublicId
				return &k
			}(),
			create:        true,
			wantCreateErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocRootKey()).Error)
			got, err := NewRootKey(tt.args.scopeId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := newRootKeyId()
				require.NoError(err)
				got.PrivateId = id
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

func TestRootKey_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	org, _ := iam.TestScopes(t, conn)

	tests := []struct {
		name            string
		key             *RootKey
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             TestRootKey(t, conn, org.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *RootKey {
				k := allocRootKey()
				id, err := newRootKeyId()
				require.NoError(t, err)
				k.PrivateId = id
				k.ScopeId = org.PublicId
				return &k
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteKey := allocRootKey()
			deleteKey.PrivateId = tt.key.PrivateId
			deletedRows, err := rw.Delete(context.Background(), &deleteKey)
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
			foundKey := allocRootKey()
			foundKey.PrivateId = tt.key.PrivateId
			err = rw.LookupById(context.Background(), &foundKey)
			require.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestRootKey_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, conn)
		k := TestRootKey(t, conn, org.PublicId)
		cp := k.Clone()
		assert.True(proto.Equal(cp.(*RootKey).RootKey, k.RootKey))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, conn)
		org2, _ := iam.TestScopes(t, conn)
		k := TestRootKey(t, conn, org.PublicId)
		k2 := TestRootKey(t, conn, org2.PublicId)

		cp := k.Clone()
		assert.True(!proto.Equal(cp.(*RootKey).RootKey, k2.RootKey))
	})
}

func TestRootKey_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultRootKeyTableName
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
			def := allocRootKey()
			require.Equal(defaultTableName, def.TableName())
			s := &RootKey{
				RootKey:   &store.RootKey{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
