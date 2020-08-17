package kms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateRootKey(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	org, proj := iam.TestScopes(t, conn)

	type args struct {
		scopeId string
		key     []byte
		opt     []Option
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
				scopeId: org.PublicId,
				key:     []byte("test key"),
			},
			wantErr: false,
		},
		{
			name: "valid-global",
			args: args{
				scopeId: "global",
				key:     []byte("valid-global"),
			},
			wantErr: false,
		},
		{
			name: "invalid-proj",
			args: args{
				scopeId: proj.PublicId,
				key:     []byte("invalid-proj"),
			},
			wantErr: true,
		},
		{
			name: "invalid-scope",
			args: args{
				scopeId: "o_notAValidScopeId",
				key:     []byte("invalid-scope"),
			},
			wantErr: true,
		},
		{
			name: "empty-scope",
			args: args{
				key: []byte("empty-scope"),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			rk, kv, err := repo.CreateRootKey(context.Background(), tt.args.scopeId, tt.args.key, tt.args.opt...)
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
			foundKey, err := repo.LookupRootKey(context.Background(), rk.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundKey, rk))

			err = db.TestVerifyOplog(t, rw, rk.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			assert.NotNil(kv.CreateTime)
			foundKeyVersion, err := repo.LookupRootKeyVersion(context.Background(), kv.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundKeyVersion, kv))

			err = db.TestVerifyOplog(t, rw, kv.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteRootKey(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, conn)

	type args struct {
		key *RootKey
		opt []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantIsError     error
	}{
		{
			name: "valid",
			args: args{
				key: TestRootKey(t, conn, org.PublicId),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-private-id",
			args: args{
				key: func() *RootKey {
					k := allocRootKey()
					return &k
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsError:     db.ErrInvalidParameter,
		},
		{
			name: "not-found",
			args: args{
				key: func() *RootKey {
					id, err := newRootKeyId()
					require.NoError(t, err)
					k := allocRootKey()
					k.PrivateId = id
					require.NoError(t, err)
					return &k
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantIsError:     db.ErrRecordNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deletedRows, err := repo.DeleteRootKey(context.Background(), tt.args.key.PrivateId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, deletedRows)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				err = db.TestVerifyOplog(t, rw, tt.args.key.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundKey, err := repo.LookupRootKey(context.Background(), tt.args.key.PrivateId)
			assert.Error(err)
			assert.Nil(foundKey)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			err = db.TestVerifyOplog(t, rw, tt.args.key.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_ListRootKeys(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper, WithLimit(testLimit))
	require.NoError(t, err)

	type args struct {
		opt []Option
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
			createCnt: repo.defaultLimit + 1,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.defaultLimit + 1,
			args:      args{},
			wantCnt:   repo.defaultLimit,
			wantErr:   false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				opt: []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocRootKey()).Error)
			testRootKeys := []*RootKey{}
			for i := 0; i < tt.createCnt; i++ {
				org, _ := iam.TestScopes(t, conn)
				testRootKeys = append(testRootKeys, TestRootKey(t, conn, org.PublicId))
			}
			assert.Equal(tt.createCnt, len(testRootKeys))
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
