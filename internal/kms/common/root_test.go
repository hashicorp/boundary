package common_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/kms/common"
	"github.com/hashicorp/boundary/internal/kms/store"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateRootKeyTx(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo, err := iam.NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)
	org, proj := iam.TestScopes(t, iamRepo)

	type args struct {
		scopeId    string
		key        []byte
		keyWrapper wrapping.Wrapper
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantIsError error
	}{
		{
			name: "valid-org",
			args: args{
				scopeId:    org.PublicId,
				key:        []byte("test key"),
				keyWrapper: wrapper,
			},
			wantErr: false,
		},
		{
			name: "valid-global",
			args: args{
				scopeId:    "global",
				key:        []byte("valid-global"),
				keyWrapper: wrapper,
			},
			wantErr: false,
		},
		{
			name: "invalid-proj",
			args: args{
				scopeId:    proj.PublicId,
				key:        []byte("invalid-proj"),
				keyWrapper: wrapper,
			},
			wantErr: true,
		},
		{
			name: "invalid-scope",
			args: args{
				scopeId:    "o_notAValidScopeId",
				key:        []byte("invalid-scope"),
				keyWrapper: wrapper,
			},
			wantErr: true,
		},
		{
			name: "empty-scope",
			args: args{
				key:        []byte("empty-scope"),
				keyWrapper: wrapper,
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				scopeId:    org.PublicId,
				key:        []byte("test key"),
				keyWrapper: nil,
			},
			wantErr:     true,
			wantIsError: db.ErrNilParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			// need to delete root keys created by iam.TestScopes()
			require.NoError(conn.Where("1=1").Delete(&kms.RootKey{RootKey: &store.RootKey{}}).Error)
			rk, kv, err := common.CreateRootKeyTx(context.Background(), rw, tt.args.keyWrapper, tt.args.scopeId, tt.args.key)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(rk)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				return
			}
			require.NoError(err)
			assert.NotNil(rk.CreateTime)
			foundKey, err := repo.LookupRootKey(context.Background(), tt.args.keyWrapper, rk.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundKey, rk))

			// make sure there was no oplog written
			err = db.TestVerifyOplog(t, rw, rk.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			assert.NotNil(kv.CreateTime)
			foundKeyVersion, err := repo.LookupRootKeyVersion(context.Background(), tt.args.keyWrapper, kv.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundKeyVersion, kv))

			// make sure there was no oplog written
			err = db.TestVerifyOplog(t, rw, kv.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
			assert.True(errors.Is(err, db.ErrRecordNotFound))
		})
	}
}
