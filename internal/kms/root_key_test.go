package kms_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// NOTE: there are no update tests since all the RootKey attributes are
// immutable and those tests are covered by TestRootKey_ImmutableFields

func TestRootKey_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	type args struct {
		scopeId string
		opt     []kms.Option
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.RootKey
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
			name: "valid-org-config",
			args: args{
				scopeId: org.PublicId,
			},
			want: func() *kms.RootKey {
				k := kms.AllocRootKey()
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
			want: func() *kms.RootKey {
				k := kms.AllocRootKey()
				k.ScopeId = "global"
				return &k
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
			got, err := kms.NewRootKey(tt.args.scopeId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(kms.RootKeyPrefix)
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
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")

	tests := []struct {
		name            string
		key             *kms.RootKey
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             kms.TestRootKey(t, conn, org.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *kms.RootKey {
				k := kms.AllocRootKey()
				id, err := db.NewPublicId(kms.RootKeyPrefix)
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
			deleteKey := kms.AllocRootKey()
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
			foundKey := kms.AllocRootKey()
			foundKey.PrivateId = tt.key.PrivateId
			err = rw.LookupById(context.Background(), &foundKey)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestRootKey_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
		k := kms.TestRootKey(t, conn, org.PublicId)
		cp := k.Clone()
		assert.True(proto.Equal(cp.(*kms.RootKey).RootKey, k.RootKey))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
		k := kms.TestRootKey(t, conn, org.PublicId)
		k2 := kms.TestRootKey(t, conn, org2.PublicId)

		cp := k.Clone()
		assert.True(!proto.Equal(cp.(*kms.RootKey).RootKey, k2.RootKey))
	})
}

func TestRootKey_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := kms.DefaultRootKeyTableName
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
			def := kms.AllocRootKey()
			require.Equal(defaultTableName, def.TableName())
			s := kms.AllocRootKey()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
