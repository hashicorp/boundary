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
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateDatabaseKeyVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestDatabaseKey(t, conn, rk.PrivateId)

	type args struct {
		key           []byte
		databaseKeyId string
		keyWrapper    wrapping.Wrapper
		opt           []kms.Option
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantIsError errors.Code
	}{
		{
			name: "valid",
			args: args{
				key:           []byte("test key"),
				keyWrapper:    rkvWrapper,
				databaseKeyId: dk.PrivateId,
			},
			wantErr: false,
		},
		{
			name: "invalid-rkv-wrapper",
			args: args{
				key:           []byte("test key"),
				keyWrapper:    wrapper,
				databaseKeyId: dk.PrivateId,
			},
			wantErr: true,
		},
		{
			name: "empty-key",
			args: args{
				key:           nil,
				keyWrapper:    wrapper,
				databaseKeyId: dk.PrivateId,
			},
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
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
			k, err := repo.CreateDatabaseKeyVersion(context.Background(), tt.args.keyWrapper, tt.args.databaseKeyId, tt.args.key, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(k)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			require.NoError(err)
			assert.NotNil(k.CreateTime)
			foundKey, err := repo.LookupDatabaseKeyVersion(context.Background(), tt.args.keyWrapper, k.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundKey, k))

			// make sure there was no oplog written
			err = db.TestVerifyOplog(t, rw, k.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestRepository_DeleteDatabaseKeyVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestDatabaseKey(t, conn, rk.PrivateId)

	type args struct {
		key *kms.DatabaseKeyVersion
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
				key: kms.TestDatabaseKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("database key")),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-private-id",
			args: args{
				key: func() *kms.DatabaseKeyVersion {
					k := kms.AllocDatabaseKeyVersion()
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
				key: func() *kms.DatabaseKeyVersion {
					id, err := db.NewPublicId(kms.DatabaseKeyPrefix)
					require.NoError(t, err)
					k := kms.AllocDatabaseKeyVersion()
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
			deletedRows, err := repo.DeleteDatabaseKeyVersion(context.Background(), tt.args.key.PrivateId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, deletedRows)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				err = db.TestVerifyOplog(t, rw, tt.args.key.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundKey, err := repo.LookupDatabaseKeyVersion(context.Background(), wrapper, tt.args.key.PrivateId)
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

func TestRepository_LatestDatabaseKeyVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestDatabaseKey(t, conn, rk.PrivateId)

	tests := []struct {
		name        string
		createCnt   int
		keyWrapper  wrapping.Wrapper
		wantVersion uint32
		wantErr     bool
		wantIsError errors.Code
	}{
		{
			name:        "5",
			createCnt:   5,
			keyWrapper:  rkvWrapper,
			wantVersion: 5,
			wantErr:     false,
		},
		{
			name:        "1",
			createCnt:   1,
			keyWrapper:  rkvWrapper,
			wantVersion: 1,
			wantErr:     false,
		},
		{
			name:        "0",
			createCnt:   0,
			keyWrapper:  rkvWrapper,
			wantErr:     true,
			wantIsError: errors.RecordNotFound,
		},
		{
			name:        "nil-wrapper",
			createCnt:   5,
			keyWrapper:  nil,
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocDatabaseKeyVersion(); return &i }(), "1=1")
			testKeys := []*kms.DatabaseKeyVersion{}
			for i := 0; i < tt.createCnt; i++ {
				k := kms.TestDatabaseKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("test database key"))
				testKeys = append(testKeys, k)
			}
			assert.Equal(tt.createCnt, len(testKeys))
			got, err := repo.LatestDatabaseKeyVersion(context.Background(), tt.keyWrapper, dk.PrivateId)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.True(errors.Match(errors.T(tt.wantIsError), err))
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.wantVersion, got.Version)
		})
	}
}

func TestRepository_ListDatabaseKeyVersions(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw, kms.WithLimit(testLimit))
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocRootKey(); return &i }(), "1=1")
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	dk := kms.TestDatabaseKey(t, conn, rk.PrivateId)

	type args struct {
		databaseKeyId string
		keyWrapper    wrapping.Wrapper
		opt           []kms.Option
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
				databaseKeyId: dk.PrivateId,
				keyWrapper:    rkvWrapper,
				opt:           []kms.Option{kms.WithLimit(-1)},
			},
			wantCnt: repo.DefaultLimit() + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.DefaultLimit() + 1,
			args: args{
				keyWrapper:    rkvWrapper,
				databaseKeyId: dk.PrivateId,
			},
			wantCnt: repo.DefaultLimit(),
			wantErr: false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.DefaultLimit() + 1,
			args: args{
				keyWrapper:    rkvWrapper,
				databaseKeyId: dk.PrivateId,
				opt:           []kms.Option{kms.WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "bad-org",
			createCnt: 1,
			args: args{
				keyWrapper:    rkvWrapper,
				databaseKeyId: "bad-id",
			},
			wantCnt: 0,
			wantErr: false,
		},
		{
			name:      "nil-wrapper",
			createCnt: 1,
			args: args{
				keyWrapper:    nil,
				databaseKeyId: dk.PrivateId,
			},
			wantCnt: 0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			db.TestDeleteWhere(t, conn, func() interface{} { i := kms.AllocDatabaseKeyVersion(); return &i }(), "1=1")
			keyVersions := []*kms.DatabaseKeyVersion{}
			for i := 0; i < tt.createCnt; i++ {
				k := kms.TestDatabaseKeyVersion(t, conn, rkvWrapper, dk.PrivateId, []byte("database key"))
				keyVersions = append(keyVersions, k)
			}
			assert.Equal(tt.createCnt, len(keyVersions))
			got, err := repo.ListDatabaseKeyVersions(context.Background(), tt.args.keyWrapper, tt.args.databaseKeyId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}
