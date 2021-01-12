package kms_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateRootKey(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)

	type args struct {
		scopeId    string
		key        []byte
		keyWrapper wrapping.Wrapper
		opt        []kms.Option
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantIsError errors.Code
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
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				scopeId:    org.PublicId,
				key:        []byte("test key"),
				keyWrapper: nil,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rk, kv, err := repo.CreateRootKey(context.Background(), tt.args.keyWrapper, tt.args.scopeId, tt.args.key, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(rk)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
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
			assert.True(errors.IsNotFoundError(err))

			assert.NotNil(kv.CreateTime)
			foundKeyVersion, err := repo.LookupRootKeyVersion(context.Background(), tt.args.keyWrapper, kv.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundKeyVersion, kv))

			// make sure there was no oplog written
			err = db.TestVerifyOplog(t, rw, kv.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestRepository_DeleteRootKey(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)

	type args struct {
		key *kms.RootKey
		opt []kms.Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsError     errors.Code
	}{
		{
			name: "valid",
			args: args{
				key: kms.TestRootKey(t, conn, org.PublicId),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-private-id",
			args: args{
				key: func() *kms.RootKey {
					k := kms.AllocRootKey()
					return &k
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsError:     errors.InvalidParameter,
		},
		{
			name: "not-found",
			args: args{
				key: func() *kms.RootKey {
					id, err := db.NewPublicId(kms.RootKeyPrefix)
					require.NoError(t, err)
					k := kms.AllocRootKey()
					k.PrivateId = id
					require.NoError(t, err)
					return &k
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsError:     errors.RecordNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := repo.DeleteRootKey(context.Background(), tt.args.key.PrivateId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, deletedRows)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				// make sure there was no oplog written
				err = db.TestVerifyOplog(t, rw, tt.args.key.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundKey, err := repo.LookupRootKey(context.Background(), wrapper, tt.args.key.PrivateId)
			assert.Error(err)
			assert.Nil(foundKey)
			assert.True(errors.IsNotFoundError(err))

			// make sure there was no oplog written
			err = db.TestVerifyOplog(t, rw, tt.args.key.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestRepository_ListRootKeys(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	rw := db.New(conn)
	repo, err := kms.NewRepository(rw, rw, kms.WithLimit(testLimit))
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)

	type args struct {
		opt []kms.Option
	}
	tests := []struct {
		name      string
		createCnt int
		args      args
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "no-limit",
			createCnt: repo.DefaultLimit() + 1,
			args: args{
				opt: []kms.Option{kms.WithLimit(-1)},
			},
			wantCnt: (repo.DefaultLimit()+1)*2 + 1, // org and project both have keys, plus global scope
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.DefaultLimit() + 1,
			args:      args{},
			wantCnt:   repo.DefaultLimit(),
			wantErr:   false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.DefaultLimit() + 1,
			args: args{
				opt: []kms.Option{kms.WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			for i := 0; i < tt.createCnt; i++ {
				_, _ = iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			}
			got, err := repo.ListRootKeys(context.Background(), tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}
