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

// NOTE: there are no update tests since all the OidcKey attributes are
// immutable and those tests are covered by TestOidcKey_ImmutableFields

func TestOidcKey_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)

	type args struct {
		rootKeyId string
		opt       []kms.Option
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.OidcKey
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
			want: func() *kms.OidcKey {
				k := kms.AllocOidcKey()
				k.RootKeyId = rk.PrivateId
				return &k
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, kms.AllocOidcKey(), "1=1")
			got, err := kms.NewOidcKey(tt.args.rootKeyId, tt.args.opt...)
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

func TestOidcKey_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	db.TestDeleteWhere(t, conn, kms.AllocOidcKey(), "1=1")

	tests := []struct {
		name            string
		key             *kms.OidcKey
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             kms.TestOidcKey(t, conn, rk.PrivateId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *kms.OidcKey {
				k := kms.AllocOidcKey()
				id, err := db.NewPublicId(kms.OidcKeyPrefix)
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
			deleteKey := kms.AllocOidcKey()
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
			foundKey := kms.AllocOidcKey()
			foundKey.PrivateId = tt.key.PrivateId
			err = rw.LookupById(context.Background(), &foundKey)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestOidcKey_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
		rk := kms.TestRootKey(t, conn, org.PublicId)
		k := kms.TestOidcKey(t, conn, rk.PrivateId)
		cp := k.Clone()
		assert.True(proto.Equal(cp.(*kms.OidcKey).OidcKey, k.OidcKey))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
		rk := kms.TestRootKey(t, conn, org.PublicId)
		rk2 := kms.TestRootKey(t, conn, org2.PublicId)
		k := kms.TestOidcKey(t, conn, rk.PrivateId)
		k2 := kms.TestOidcKey(t, conn, rk2.PrivateId)

		cp := k.Clone()
		assert.True(!proto.Equal(cp.(*kms.OidcKey).OidcKey, k2.OidcKey))
	})
}

func TestOidcKey_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := kms.DefaultOidcKeyTableName
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
			def := kms.AllocOidcKey()
			require.Equal(defaultTableName, def.TableName())
			s := kms.AllocOidcKey()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
