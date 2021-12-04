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

// NOTE: there are no update tests since all the TokenKeyVersion attributes are
// immutable and those tests are covered by TestTokenKey_ImmutableFields

func TestTokenKeyVersion_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	rkv, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)

	dk := kms.TestTokenKey(t, conn, rk.PrivateId)

	type args struct {
		tokenKeyId       string
		key              []byte
		rootKeyVersionId string
		opt              []kms.Option
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.TokenKeyVersion
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "empty-id",
			args: args{
				key:              []byte("test key"),
				rootKeyVersionId: rkv.PrivateId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-key",
			args: args{
				tokenKeyId:       dk.PrivateId,
				rootKeyVersionId: rkv.PrivateId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-root-key-version-id",
			args: args{
				tokenKeyId: dk.PrivateId,
				key:        []byte("test key"),
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				tokenKeyId:       dk.PrivateId,
				key:              []byte("test key"),
				rootKeyVersionId: rkv.PrivateId,
			},
			want: func() *kms.TokenKeyVersion {
				k := kms.AllocTokenKeyVersion()
				k.RootKeyVersionId = rkv.PrivateId
				k.Key = []byte("test key")
				k.TokenKeyId = dk.PrivateId
				return &k
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, kms.AllocTokenKeyVersion(), "1=1")
			got, err := kms.NewTokenKeyVersion(tt.args.tokenKeyId, tt.args.key, tt.args.rootKeyVersionId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(kms.TokenKeyPrefix)
				require.NoError(err)
				got.PrivateId = id
				err = got.Encrypt(context.Background(), rkvWrapper)
				require.NoError(err)
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

func TestTokenKeyVersion_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	tk := kms.TestTokenKey(t, conn, rk.PrivateId)

	db.TestDeleteWhere(t, conn, kms.AllocTokenKeyVersion(), "1=1")

	tests := []struct {
		name            string
		key             *kms.TokenKeyVersion
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             kms.TestTokenKeyVersion(t, conn, rkvWrapper, tk.PrivateId, []byte("test key")),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *kms.TokenKeyVersion {
				k := kms.AllocTokenKeyVersion()
				id, err := db.NewPublicId(kms.TokenKeyVersionPrefix)
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
			deleteKey := kms.AllocTokenKeyVersion()
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
			foundKey := kms.AllocTokenKeyVersion()
			foundKey.PrivateId = tt.key.PrivateId
			err = rw.LookupById(context.Background(), &foundKey)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestTokenKeyVersion_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")

		rk := kms.TestRootKey(t, conn, org.PublicId)
		_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)

		k := kms.TestTokenKey(t, conn, rk.PrivateId)
		kv := kms.TestTokenKeyVersion(t, conn, rkvWrapper, k.PrivateId, []byte("test key"))
		cp := kv.Clone()
		assert.True(proto.Equal(cp.(*kms.TokenKeyVersion).TokenKeyVersion, kv.TokenKeyVersion))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
		rk := kms.TestRootKey(t, conn, org.PublicId)
		rk2 := kms.TestRootKey(t, conn, org2.PublicId)
		_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
		_, rkvWrapper2 := kms.TestRootKeyVersion(t, conn, wrapper, rk2.PrivateId)

		k := kms.TestTokenKey(t, conn, rk.PrivateId)
		k2 := kms.TestTokenKey(t, conn, rk2.PrivateId)
		kv := kms.TestTokenKeyVersion(t, conn, rkvWrapper, k.PrivateId, []byte("test key"))
		kv2 := kms.TestTokenKeyVersion(t, conn, rkvWrapper2, k2.PrivateId, []byte("test key 2"))

		cp := kv.Clone()
		assert.True(!proto.Equal(cp.(*kms.TokenKeyVersion).TokenKeyVersion, kv2.TokenKeyVersion))
	})
}

func TestTokenKeyVersion_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := kms.DefaultTokenKeyVersionTableName
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
			def := kms.AllocTokenKeyVersion()
			require.Equal(defaultTableName, def.TableName())
			s := kms.AllocTokenKeyVersion()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
