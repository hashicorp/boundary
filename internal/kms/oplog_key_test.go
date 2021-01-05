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

// NOTE: there are no update tests since all the OplogKey attributes are
// immutable and those tests are covered by TestOplogKey_ImmutableFields

func TestOplogKey_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)

	type args struct {
		rootKeyId string
		opt       []kms.Option
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.OplogKey
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name:      "empty-rootKeyId",
			args:      args{},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				rootKeyId: rk.PrivateId,
			},
			want: func() *kms.OplogKey {
				k := kms.AllocOplogKey()
				k.RootKeyId = rk.PrivateId
				return &k
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(kms.AllocOplogKey()).Error)
			got, err := kms.NewOplogKey(tt.args.rootKeyId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(kms.OplogKeyPrefix)
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

func TestOplogKey_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocOplogKey()).Error)

	tests := []struct {
		name            string
		key             *kms.OplogKey
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             kms.TestOplogKey(t, conn, rk.PrivateId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *kms.OplogKey {
				k := kms.AllocOplogKey()
				id, err := db.NewPublicId(kms.OplogKeyPrefix)
				require.NoError(t, err)
				k.PrivateId = id
				k.RootKeyId = rk.PrivateId
				return &k
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteKey := kms.AllocOplogKey()
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
			foundKey := kms.AllocOplogKey()
			foundKey.PrivateId = tt.key.PrivateId
			err = rw.LookupById(context.Background(), &foundKey)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestOplogKey_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
		rk := kms.TestRootKey(t, conn, org.PublicId)
		k := kms.TestOplogKey(t, conn, rk.PrivateId)
		cp := k.Clone()
		assert.True(proto.Equal(cp.(*kms.OplogKey).OplogKey, k.OplogKey))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
		rk := kms.TestRootKey(t, conn, org.PublicId)
		rk2 := kms.TestRootKey(t, conn, org2.PublicId)
		k := kms.TestOplogKey(t, conn, rk.PrivateId)
		k2 := kms.TestOplogKey(t, conn, rk2.PrivateId)

		cp := k.Clone()
		assert.True(!proto.Equal(cp.(*kms.OplogKey).OplogKey, k2.OplogKey))
	})
}

func TestOplogKey_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := kms.DefaultOplogKeyTableName
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
			def := kms.AllocOplogKey()
			require.Equal(defaultTableName, def.TableName())
			s := kms.AllocOplogKey()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
