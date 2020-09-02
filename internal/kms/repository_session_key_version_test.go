package kms_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateSessionKeyVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	sk := kms.TestSessionKey(t, conn, rk.PrivateId)

	type args struct {
		key          []byte
		sessionKeyId string
		keyWrapper   wrapping.Wrapper
		opt          []kms.Option
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantIsError error
	}{
		{
			name: "valid",
			args: args{
				key:          []byte("test key"),
				keyWrapper:   rkvWrapper,
				sessionKeyId: sk.PrivateId,
			},
			wantErr: false,
		},
		{
			name: "invalid-rkv-wrapper",
			args: args{
				key:          []byte("test key"),
				keyWrapper:   wrapper,
				sessionKeyId: sk.PrivateId,
			},
			wantErr: true,
		},
		{
			name: "empty-key",
			args: args{
				key:          nil,
				keyWrapper:   wrapper,
				sessionKeyId: sk.PrivateId,
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				key:        []byte("test key"),
				keyWrapper: nil,
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			k, err := repo.CreateSessionKeyVersion(context.Background(), tt.args.keyWrapper, tt.args.sessionKeyId, tt.args.key, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(k)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				return
			}
			require.NoError(err)
			assert.NotNil(k.CreateTime)
			foundKey, err := repo.LookupSessionKeyVersion(context.Background(), tt.args.keyWrapper, k.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundKey, k))

			// make sure there was no oplog written
			err = db.TestVerifyOplog(t, rw, k.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestRepository_DeleteSessionKeyVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	sk := kms.TestSessionKey(t, conn, rk.PrivateId)

	type args struct {
		key *kms.SessionKeyVersion
		opt []kms.Option
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
				key: kms.TestSessionKeyVersion(t, conn, rkvWrapper, sk.PrivateId, []byte("session key")),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-private-id",
			args: args{
				key: func() *kms.SessionKeyVersion {
					k := kms.AllocSessionKeyVersion()
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
				key: func() *kms.SessionKeyVersion {
					id, err := db.NewPublicId(kms.SessionKeyPrefix)
					require.NoError(t, err)
					k := kms.AllocSessionKeyVersion()
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
			deletedRows, err := repo.DeleteSessionKeyVersion(context.Background(), tt.args.key.PrivateId, tt.args.opt...)
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
			foundKey, err := repo.LookupSessionKeyVersion(context.Background(), wrapper, tt.args.key.PrivateId)
			assert.Error(err)
			assert.Nil(foundKey)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			// make sure there was no oplog written
			err = db.TestVerifyOplog(t, rw, tt.args.key.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
			assert.True(errors.Is(db.ErrRecordNotFound, err))
		})
	}
}

func TestRepository_LatestSessionKeyVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	sk := kms.TestSessionKey(t, conn, rk.PrivateId)

	tests := []struct {
		name        string
		createCnt   int
		keyWrapper  wrapping.Wrapper
		wantVersion uint32
		wantErr     bool
		wantIsError error
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
			wantIsError: db.ErrRecordNotFound,
		},
		{
			name:        "nil-wrapper",
			createCnt:   5,
			keyWrapper:  nil,
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(kms.AllocSessionKeyVersion()).Error)
			testKeys := []*kms.SessionKeyVersion{}
			for i := 0; i < tt.createCnt; i++ {
				k := kms.TestSessionKeyVersion(t, conn, rkvWrapper, sk.PrivateId, []byte("test key"))
				testKeys = append(testKeys, k)
			}
			assert.Equal(tt.createCnt, len(testKeys))
			got, err := repo.LatestSessionKeyVersion(context.Background(), tt.keyWrapper, sk.PrivateId)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.wantVersion, got.Version)
		})
	}
}

func TestRepository_ListSessionKeyVersions(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := kms.NewRepository(rw, rw, kms.WithLimit(testLimit))
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	rk := kms.TestRootKey(t, conn, org.PublicId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, conn, wrapper, rk.PrivateId)
	sk := kms.TestSessionKey(t, conn, rk.PrivateId)

	type args struct {
		sessionKeyId string
		keyWrapper   wrapping.Wrapper
		opt          []kms.Option
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
				sessionKeyId: sk.PrivateId,
				keyWrapper:   rkvWrapper,
				opt:          []kms.Option{kms.WithLimit(-1)},
			},
			wantCnt: repo.DefaultLimit() + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.DefaultLimit() + 1,
			args: args{
				keyWrapper:   rkvWrapper,
				sessionKeyId: sk.PrivateId,
			},
			wantCnt: repo.DefaultLimit(),
			wantErr: false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.DefaultLimit() + 1,
			args: args{
				keyWrapper:   rkvWrapper,
				sessionKeyId: sk.PrivateId,
				opt:          []kms.Option{kms.WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "bad-org",
			createCnt: 1,
			args: args{
				keyWrapper:   rkvWrapper,
				sessionKeyId: "bad-id",
			},
			wantCnt: 0,
			wantErr: false,
		},
		{
			name:      "nil-wrapper",
			createCnt: 1,
			args: args{
				keyWrapper:   nil,
				sessionKeyId: sk.PrivateId,
			},
			wantCnt: 0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(kms.AllocSessionKeyVersion()).Error)
			keyVersions := []*kms.SessionKeyVersion{}
			for i := 0; i < tt.createCnt; i++ {
				k := kms.TestSessionKeyVersion(t, conn, rkvWrapper, sk.PrivateId, []byte("session key"))
				keyVersions = append(keyVersions, k)
			}
			assert.Equal(tt.createCnt, len(keyVersions))
			got, err := repo.ListSessionKeyVersions(context.Background(), tt.args.keyWrapper, tt.args.sessionKeyId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
}
