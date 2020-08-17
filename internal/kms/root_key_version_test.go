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

// NOTE: there are no update tests since all the RootKeyVersion attributes are
// immutable and those tests are covered by TestRootKeyVersion_ImmutableFields

func TestRootKeyVersion_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, conn)
	rootKey := TestRootKey(t, conn, org.PublicId)
	type args struct {
		rootId string
		key    []byte
		opt    []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *RootKeyVersion
		wantErr       bool
		wantIsErr     error
		create        bool
		wantCreateErr bool
	}{
		{
			name: "empty-root-id",
			args: args{
				key: []byte("test key"),
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "empty-key",
			args: args{
				rootId: rootKey.PrivateId,
			},
			wantErr:   true,
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid",
			args: args{
				rootId: rootKey.PrivateId,
				key:    []byte("test key"),
			},
			want: func() *RootKeyVersion {
				k := allocRootKeyVersion()
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
			require.NoError(conn.Where("1=1").Delete(allocRootKeyVersion()).Error)
			got, err := NewRootKeyVersion(tt.args.rootId, tt.args.key, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Is(err, tt.wantIsErr))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := newRootKeyVersionId()
				require.NoError(err)
				got.PrivateId = id
				err = got.encrypt(context.Background(), wrapper)
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
	rw := db.New(conn)
	org, _ := iam.TestScopes(t, conn)
	wrapper := db.TestWrapper(t)
	rk := TestRootKey(t, conn, org.PublicId)

	tests := []struct {
		name            string
		key             *RootKeyVersion
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			key:             TestRootKeyVersion(t, conn, wrapper, rk.PrivateId, []byte("test key")),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name: "bad-id",
			key: func() *RootKeyVersion {
				k := allocRootKeyVersion()
				id, err := newRootKeyVersionId()
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
			deleteKey := allocRootKeyVersion()
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

func TestRootKeyVersion_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, conn)
		rk := TestRootKey(t, conn, org.PublicId)
		k := TestRootKeyVersion(t, conn, wrapper, rk.PrivateId, []byte("test key"))
		cp := k.Clone()
		assert.True(proto.Equal(cp.(*RootKeyVersion).RootKeyVersion, k.RootKeyVersion))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, conn)
		rk := TestRootKey(t, conn, org.PublicId)
		k := TestRootKeyVersion(t, conn, wrapper, rk.PrivateId, []byte("test key"))
		k2 := TestRootKeyVersion(t, conn, wrapper, rk.PrivateId, []byte("test key"))
		cp := k.Clone()
		assert.True(!proto.Equal(cp.(*RootKeyVersion).RootKeyVersion, k2.RootKeyVersion))
	})
}

func TestRootKeyVersion_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultRootKeyVersionTableName
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
			def := allocRootKeyVersion()
			require.Equal(defaultTableName, def.TableName())
			s := &RootKeyVersion{
				RootKeyVersion: &store.RootKeyVersion{},
				tableName:      tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
