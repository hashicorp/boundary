package kms_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/kms/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// NOTE: there are no update tests since all the RootKeyVersion attributes are
// immutable and those tests are covered by TestRootKeyVersion_ImmutableFields

func TestRootKeyVersion_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rootKey := kms.TestRootKey(t, conn, org.PublicId)
	type args struct {
		rootId string
		key    []byte
		opt    []kms.Option
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.RootKeyVersion
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "empty-root-id",
			args: args{
				key: []byte("test key"),
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-key",
			args: args{
				rootId: rootKey.PrivateId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				rootId: rootKey.PrivateId,
				key:    []byte("test key"),
			},
			want: func() *kms.RootKeyVersion {
				k := kms.AllocRootKeyVersion()
				k.RootKeyId = rootKey.PrivateId
				k.Key = []byte("test key")
				return &k
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(kms.AllocRootKeyVersion()).Error)
			got, err := kms.NewRootKeyVersion(tt.args.rootId, tt.args.key, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(kms.RootKeyVersionPrefix)
				require.NoError(err)
				got.PrivateId = id
				err = got.Encrypt(context.Background(), wrapper)
				require.NoError(err)
				err = db.New(conn).Create(context.Background(), got)
				if tt.wantCreateErr {
					assert.Error(err)
					return
				} else {
					assert.NoError(err)
				}
				assert.Equal(uint32(1), got.Version)
			}
		})
	}
}

func TestRootKeyVersion_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)

	tests := []struct {
		name            string
		key             *kms.RootKeyVersion
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             func() *kms.RootKeyVersion { k, _ := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId); return k }(),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *kms.RootKeyVersion {
				k := kms.AllocRootKeyVersion()
				id, err := db.NewPublicId(kms.RootKeyVersionPrefix)
				require.NoError(t, err)
				k.PrivateId = id
				return &k
			}(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteKey := kms.AllocRootKeyVersion()
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

func TestRootKeyVersion_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
		rk := kms.TestRootKey(t, conn, org.PublicId)
		k, _ := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
		cp := k.Clone()
		assert.True(proto.Equal(cp.(*kms.RootKeyVersion).RootKeyVersion, k.RootKeyVersion))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
		rk := kms.TestRootKey(t, conn, org.PublicId)
		k, _ := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
		k2, _ := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
		cp := k.Clone()
		assert.True(!proto.Equal(cp.(*kms.RootKeyVersion).RootKeyVersion, k2.RootKeyVersion))
	})
}

func TestRootKeyVersion_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := kms.DefaultRootKeyVersionTableName
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
			def := kms.AllocRootKeyVersion()
			require.Equal(defaultTableName, def.TableName())
			s := &kms.RootKeyVersion{
				RootKeyVersion: &store.RootKeyVersion{},
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
