package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_ListConnection(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms, WithLimit(testLimit))
	require.NoError(t, err)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)

	type args struct {
		searchForSessionId string
		opt                []Option
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
				searchForSessionId: session.PublicId,
				opt:                []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				searchForSessionId: session.PublicId,
			},
			wantCnt: repo.defaultLimit,
			wantErr: false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				searchForSessionId: session.PublicId,
				opt:                []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "bad-session-id",
			createCnt: repo.defaultLimit + 1,
			args: args{
				searchForSessionId: "s_thisIsNotValid",
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(AllocConnection()).Error)
			testConnections := []*Connection{}
			for i := 0; i < tt.createCnt; i++ {
				c := TestConnection(t, conn,
					session.PublicId,
					"127.0.0.1",
					22,
					"127.0.0.1",
					2222,
				)
				testConnections = append(testConnections, c)
			}
			assert.Equal(tt.createCnt, len(testConnections))
			got, err := repo.ListConnections(context.Background(), tt.args.searchForSessionId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
	t.Run("withOrder", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		require.NoError(conn.Where("1=1").Delete(AllocConnection()).Error)
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestConnection(t, conn,
				session.PublicId,
				"127.0.0.1",
				22,
				"127.0.0.1",
				2222,
			)
		}
		got, err := repo.ListConnections(context.Background(), session.PublicId, WithOrder("create_time asc"))
		require.NoError(err)
		assert.Equal(wantCnt, len(got))

		for i := 0; i < len(got)-1; i++ {
			first, err := ptypes.Timestamp(got[i].CreateTime.Timestamp)
			require.NoError(err)
			second, err := ptypes.Timestamp(got[i+1].CreateTime.Timestamp)
			require.NoError(err)
			assert.True(first.Before(second))
		}
	})
}

func TestRepository_DeleteConnection(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)

	type args struct {
		connection *Connection
		opt        []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			args: args{
				connection: TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				connection: func() *Connection {
					c := AllocConnection()
					return &c
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete connection: missing public id invalid parameter",
		},
		{
			name: "not-found",
			args: args{
				connection: func() *Connection {
					c := AllocConnection()
					id, err := newConnectionId()
					require.NoError(t, err)
					c.PublicId = id
					return &c
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete connection: failed record not found for ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteConnection(context.Background(), tt.args.connection.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.connection.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found, _, err := repo.LookupConnection(context.Background(), tt.args.connection.PublicId)
			assert.NoError(err)
			assert.Nil(found)

			err = db.TestVerifyOplog(t, rw, tt.args.connection.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
		})
	}
}
