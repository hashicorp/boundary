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

// NOTE: there are no update tests since all the AuditKeyVersion attributes are
// immutable and those tests are covered by TestAuditKey_ImmutableFields

func TestAuditKeyVersion_Create(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	rkv, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)

	dk := kms.TestAuditKey(t, conn, rk.PrivateId)

	type args struct {
		AuditKeyId       string
		key              []byte
		rootKeyVersionId string
		opt              []kms.Option
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.AuditKeyVersion
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "empty-audit-id",
			args: args{
				key:              []byte("audit key"),
				rootKeyVersionId: rkv.PrivateId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-key",
			args: args{
				AuditKeyId:       dk.PrivateId,
				rootKeyVersionId: rkv.PrivateId,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-root-key-version-id",
			args: args{
				AuditKeyId: dk.PrivateId,
				key:        []byte("audit key"),
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				AuditKeyId:       dk.PrivateId,
				key:              []byte("audit key"),
				rootKeyVersionId: rkv.PrivateId,
			},
			want: func() *kms.AuditKeyVersion {
				k := kms.AllocAuditKeyVersion()
				k.RootKeyVersionId = rkv.PrivateId
				k.Key = []byte("audit key")
				k.AuditKeyId = dk.PrivateId
				return &k
			}(),
			create: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, kms.AllocAuditKeyVersion(), "1=1")
			got, err := kms.NewAuditKeyVersion(testCtx, tt.args.AuditKeyId, tt.args.key, tt.args.rootKeyVersionId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := db.NewPublicId(kms.AuditKeyPrefix)
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

func TestAuditKeyVersion_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestAuditKey(t, conn, rk.PrivateId)

	db.TestDeleteWhere(t, conn, kms.AllocAuditKeyVersion(), "1=1")

	tests := []struct {
		name            string
		key             *kms.AuditKeyVersion
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             kms.TestAuditKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("audit key")),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *kms.AuditKeyVersion {
				k := kms.AllocAuditKeyVersion()
				id, err := db.NewPublicId(kms.AuditKeyVersionPrefix)
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
			deleteKey := kms.AllocAuditKeyVersion()
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
			foundKey := kms.AllocAuditKeyVersion()
			foundKey.PrivateId = tt.key.PrivateId
			err = rw.LookupById(context.Background(), &foundKey)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestAuditKeyVersion_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		db.TestDeleteWhere(t, conn, kms.AllocRootKey(), "1=1")

		rk := kms.TestRootKey(t, conn, org.PublicId)
		_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)

		k := kms.TestAuditKey(t, conn, rk.PrivateId)
		kv := kms.TestAuditKeyVersion(t, conn, rkvWrapper, k.PrivateId, []byte("test db key"))
		cp := kv.Clone()
		assert.True(proto.Equal(cp.(*kms.AuditKeyVersion).AuditKeyVersion, kv.AuditKeyVersion))
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

		k := kms.TestAuditKey(t, conn, rk.PrivateId)
		k2 := kms.TestAuditKey(t, conn, rk2.PrivateId)
		kv := kms.TestAuditKeyVersion(t, conn, rkvWrapper, k.PrivateId, []byte("test db key"))
		kv2 := kms.TestAuditKeyVersion(t, conn, rkvWrapper2, k2.PrivateId, []byte("test db key 2"))

		cp := kv.Clone()
		assert.True(!proto.Equal(cp.(*kms.AuditKeyVersion).AuditKeyVersion, kv2.AuditKeyVersion))
	})
}

func TestAuditKeyVersion_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := kms.DefaultAuditKeyVersionTableName
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
			def := kms.AllocAuditKeyVersion()
			require.Equal(defaultTableName, def.TableName())
			s := kms.AllocAuditKeyVersion()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
