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

func TestRepository_CreateRootKeyVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, conn)
	rk := TestRootKey(t, conn, org.PublicId)

	type args struct {
		key *RootKeyVersion
		opt []Option
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
				key: func() *RootKeyVersion {
					k, err := NewRootKeyVersion(rk.PrivateId, "test key")
					assert.NoError(t, err)
					return k
				}(),
			},
			wantErr: false,
		},
		{
			name: "invalid-root-key",
			args: args{
				key: func() *RootKeyVersion {
					k, err := NewRootKeyVersion("krk_thisIsNotValid", "test key")
					assert.NoError(t, err)
					return k
				}(),
			},
			wantErr: true,
		},
		{
			name: "empty-key",
			args: args{
				key: func() *RootKeyVersion {
					k, err := NewRootKeyVersion(rk.PrivateId, "test key")
					assert.NoError(t, err)
					k.Key = ""
					return k
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "invalid-privateId",
			args: args{
				key: func() *RootKeyVersion {
					k, err := NewRootKeyVersion(rk.PrivateId, "test key")
					assert.NoError(t, err)
					k.PrivateId = "mustBeEmpty"
					return k
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "invalid-version",
			args: args{
				key: func() *RootKeyVersion {
					k, err := NewRootKeyVersion(rk.PrivateId, "test key")
					assert.NoError(t, err)
					k.Version = 5675309
					return k
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "nil-store",
			args: args{
				key: func() *RootKeyVersion {
					return &RootKeyVersion{
						RootKeyVersion: nil,
					}
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrNilParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			k, err := repo.CreateRootKeyVersion(context.Background(), tt.args.key, tt.args.opt...)
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
			foundKey, err := repo.LookupRootKeyVersion(context.Background(), k.PrivateId)
			assert.NoError(err)
			assert.True(proto.Equal(foundKey, k))

			err = db.TestVerifyOplog(t, rw, k.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteRootKeyVersion(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, conn)
	rk := TestRootKey(t, conn, org.PublicId)

	type args struct {
		key *RootKeyVersion
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
				key: TestRootKeyVersion(t, conn, wrapper, rk.PrivateId, "test key"),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-private-id",
			args: args{
				key: func() *RootKeyVersion {
					k := allocRootKeyVersion()
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
				key: func() *RootKeyVersion {
					id, err := newRootKeyVersionId()
					require.NoError(t, err)
					k := allocRootKeyVersion()
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
			deletedRows, err := repo.DeleteRootKeyVersion(context.Background(), tt.args.key.PrivateId, tt.args.opt...)
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
			foundKey, err := repo.LookupRootKeyVersion(context.Background(), tt.args.key.PrivateId)
			assert.Error(err)
			assert.Nil(foundKey)
			assert.True(errors.Is(err, db.ErrRecordNotFound))

			err = db.TestVerifyOplog(t, rw, tt.args.key.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
