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

// NOTE: there are no update tests since all the OidcKeyVersion attributes are
// immutable and those tests are covered by TestOidcKey_ImmutableFields

func TestOidcKeyVersion_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	rkv, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)

	dk := kms.TestOidcKey(t, conn, rk.PrivateId)

	type args struct {
		OidcKeyId        string
		key              []byte
		rootKeyVersionId string
		opt              []kms.Option
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.OidcKeyVersion
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "empty-oidc-id",
			args: args{
				key:              []byte("oidc key"),
				rootKeyVersionId: rkv.PrivateId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-key",
			args: args{
				OidcKeyId:        dk.PrivateId,
				rootKeyVersionId: rkv.PrivateId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-root-key-version-id",
			args: args{
				OidcKeyId: dk.PrivateId,
				key:       []byte("oidc key"),
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				OidcKeyId:        dk.PrivateId,
				key:              []byte("oidc key"),
				rootKeyVersionId: rkv.PrivateId,
			},
			want: func() *kms.OidcKeyVersion {
				k := kms.AllocOidcKeyVersion()
				k.RootKeyVersionId = rkv.PrivateId
				k.Key = []byte("oidc key")
				k.OidcKeyId = dk.PrivateId
				return &k
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, kms.AllocOidcKeyVersion(), "1=1")
			got, err := kms.NewOidcKeyVersion(tt.args.OidcKeyId, tt.args.key, tt.args.rootKeyVersionId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(kms.OidcKeyPrefix)
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

func TestOidcKeyVersion_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestOidcKey(t, conn, rk.PrivateId)

	db.TestDeleteWhere(t, conn, kms.AllocOidcKeyVersion(), "1=1")

	tests := []struct {
		name            string
		key             *kms.OidcKeyVersion
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             kms.TestOidcKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("oidc key")),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *kms.OidcKeyVersion {
				k := kms.AllocOidcKeyVersion()
				id, err := db.NewPublicId(kms.OidcKeyVersionPrefix)
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
			deleteKey := kms.AllocOidcKeyVersion()
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
			foundKey := kms.AllocOidcKeyVersion()
			foundKey.PrivateId = tt.key.PrivateId
			err = rw.LookupById(context.Background(), &foundKey)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestOidcKeyVersion_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")

		rk := kms.TestRootKey(t, conn, org.PublicId)
		_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)

		k := kms.TestOidcKey(t, conn, rk.PrivateId)
		kv := kms.TestOidcKeyVersion(t, conn, rkvWrapper, k.PrivateId, []byte("test db key"))
		cp := kv.Clone()
		assert.True(proto.Equal(cp.(*kms.OidcKeyVersion).OidcKeyVersion, kv.OidcKeyVersion))
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

		k := kms.TestOidcKey(t, conn, rk.PrivateId)
		k2 := kms.TestOidcKey(t, conn, rk2.PrivateId)
		kv := kms.TestOidcKeyVersion(t, conn, rkvWrapper, k.PrivateId, []byte("test db key"))
		kv2 := kms.TestOidcKeyVersion(t, conn, rkvWrapper2, k2.PrivateId, []byte("test db key 2"))

		cp := kv.Clone()
		assert.True(!proto.Equal(cp.(*kms.OidcKeyVersion).OidcKeyVersion, kv2.OidcKeyVersion))
	})
}

func TestOidcKeyVersion_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := kms.DefaultOidcKeyVersionTableName
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
			def := kms.AllocOidcKeyVersion()
			require.Equal(defaultTableName, def.TableName())
			s := kms.AllocOidcKeyVersion()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
