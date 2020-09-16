package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
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

func TestRepository_CreateConnection(t *testing.T) {
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
				connection: func() *Connection {
					c, err := NewConnection(
						session.PublicId,
						"127.0.0.1",
						22,
						"127.0.0.1",
						2222,
					)
					require.NoError(t, err)
					return c
				}(),
			},
			wantErr: false,
		},
		{
			name: "empty-session-id",
			args: args{
				connection: &Connection{
					ClientTcpAddress:  "127.0.0.1",
					ClientTcpPort:     22,
					BackendTcpAddress: "127.0.0.1",
					BackendTcpPort:    2222,
				},
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-client-address",
			args: args{
				connection: &Connection{
					SessionId:         session.PublicId,
					ClientTcpPort:     22,
					BackendTcpAddress: "127.0.0.1",
					BackendTcpPort:    2222,
				},
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-client-port",
			args: args{
				connection: &Connection{
					SessionId:         session.PublicId,
					ClientTcpAddress:  "127.0.0.1",
					BackendTcpAddress: "127.0.0.1",
					BackendTcpPort:    2222,
				},
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-backend-address",
			args: args{
				connection: &Connection{
					SessionId:        session.PublicId,
					ClientTcpAddress: "127.0.0.1",
					ClientTcpPort:    22,
					BackendTcpPort:   2222,
				},
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-backend-port",
			args: args{
				connection: &Connection{
					SessionId:         session.PublicId,
					ClientTcpAddress:  "127.0.0.1",
					ClientTcpPort:     22,
					BackendTcpAddress: "127.0.0.1",
				},
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			connection, st, err := repo.CreateConnection(context.Background(), tt.args.connection)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(connection)
				assert.Nil(st)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				return
			}
			require.NoError(err)
			assert.NotNil(connection.CreateTime)
			assert.NotNil(st.StartTime)
			assert.Equal(st.Status, StatusConnected.String())
			found, foundStates, err := repo.LookupConnection(context.Background(), connection.PublicId)
			assert.NoError(err)
			assert.Equal(found, connection)

			err = db.TestVerifyOplog(t, rw, connection.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)

			require.Equal(1, len(foundStates))
			assert.Equal(foundStates[0].Status, StatusConnected.String())
		})
	}
}

func TestRepository_UpdateConnectionState(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)

	tests := []struct {
		name                      string
		connection                *Connection
		newStatus                 ConnectionStatus
		overrideConnectionId      *string
		overrideConnectionVersion *uint32
		wantStateCnt              int
		wantErr                   bool
		wantIsError               error
	}{
		{
			name:         "closed",
			connection:   TestConnection(t, conn, session.PublicId, "0.0.0.0", 22, "0.0.0.0", 2222),
			newStatus:    StatusClosed,
			wantStateCnt: 2,
			wantErr:      false,
		},
		{
			name:       "bad-version",
			connection: TestConnection(t, conn, session.PublicId, "0.0.0.0", 22, "0.0.0.0", 2222),
			newStatus:  StatusClosed,
			overrideConnectionVersion: func() *uint32 {
				v := uint32(22)
				return &v
			}(),
			wantErr: true,
		},
		{
			name:       "empty-version",
			connection: TestConnection(t, conn, session.PublicId, "0.0.0.0", 22, "0.0.0.0", 2222),
			newStatus:  StatusClosed,
			overrideConnectionVersion: func() *uint32 {
				v := uint32(0)
				return &v
			}(),
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name:       "bad-connectionId",
			connection: TestConnection(t, conn, session.PublicId, "0.0.0.0", 22, "0.0.0.0", 2222),
			newStatus:  StatusClosed,
			overrideConnectionId: func() *string {
				s := "sc_thisIsNotValid"
				return &s
			}(),
			wantErr: true,
		},
		{
			name:       "empty-connectionId",
			connection: TestConnection(t, conn, session.PublicId, "0.0.0.0", 22, "0.0.0.0", 2222),
			newStatus:  StatusClosed,
			overrideConnectionId: func() *string {
				s := ""
				return &s
			}(),
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var id string
			var version uint32
			switch {
			case tt.overrideConnectionId != nil:
				id = *tt.overrideConnectionId
			default:
				id = tt.connection.PublicId
			}
			switch {
			case tt.overrideConnectionVersion != nil:
				version = *tt.overrideConnectionVersion
			default:
				version = tt.connection.Version
			}

			s, ss, err := repo.UpdateConnectionState(context.Background(), id, version, tt.newStatus)
			if tt.wantErr {
				require.Error(err)
				if tt.wantIsError != nil {
					assert.Truef(errors.Is(err, tt.wantIsError), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(ss)
			assert.Equal(tt.wantStateCnt, len(ss))
			assert.Equal(tt.newStatus.String(), ss[0].Status)
		})
	}
}

func TestRepository_UpdateConnection(t *testing.T) {
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
		closedReason      ClosedReason
		bytesUp           uint64
		bytesDown         uint64
		fieldMaskPaths    []string
		opt               []Option
		publicId          *string // not updateable - db.ErrInvalidFieldMask
		sessionId         string  // not updateable - db.ErrInvalidFieldMask
		clientTcpAddress  string  // not updateable - db.ErrInvalidFieldMask
		clientTcpPort     uint32  // not updateable - db.ErrInvalidFieldMask
		backendTcpAddress string  // not updateable - db.ErrInvalidFieldMask
		backendTcpPort    uint32  // not updateable - db.ErrInvalidFieldMask
	}
	tests := []struct {
		name           string
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantIsError    error
	}{
		{
			name: "valid",
			args: args{
				closedReason:   ConnectionClosedByUser,
				bytesUp:        uint64(111),
				bytesDown:      uint64(1),
				fieldMaskPaths: []string{"ClosedReason", "BytesUp", "BytesDown"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "publicId",
			args: args{
				publicId: func() *string {
					id, err := newConnectionId()
					require.NoError(t, err)
					return &id
				}(),
				fieldMaskPaths: []string{"PublicId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "sessionId",
			args: args{
				sessionId: func() string {
					id, err := newId()
					require.NoError(t, err)
					return id
				}(),
				fieldMaskPaths: []string{"SessionId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "clientTcpAddress",
			args: args{
				clientTcpAddress: "127.0.0.1",
				fieldMaskPaths:   []string{"ClientTcpAddress"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "clientTcpPort",
			args: args{
				clientTcpPort:  443,
				fieldMaskPaths: []string{"ClientTcpPort"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "backendTcpAddress",
			args: args{
				backendTcpAddress: "127.0.0.1",
				fieldMaskPaths:    []string{"BackendTcpAddress"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "backendTcpPort",
			args: args{
				backendTcpPort: 4443,
				fieldMaskPaths: []string{"BackendTcpPort"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			c := TestConnection(t, conn, session.PublicId, "0.0.0.0", 22, "127.0.0.1", 2222)

			updateConnection := AllocConnection()
			updateConnection.PublicId = c.PublicId
			if tt.args.publicId != nil {
				updateConnection.PublicId = *tt.args.publicId
			}
			updateConnection.BytesUp = tt.args.bytesUp
			updateConnection.BytesDown = tt.args.bytesDown
			updateConnection.ClosedReason = tt.args.closedReason.String()
			updateConnection.Version = c.Version
			afterUpdate, afterUpdateState, updatedRows, err := repo.UpdateConnection(context.Background(), &updateConnection, updateConnection.Version, tt.args.fieldMaskPaths, tt.args.opt...)

			if tt.wantErr {
				require.Error(err)
				if tt.wantIsError != nil {
					assert.Truef(errors.Is(err, tt.wantIsError), "unexpected error: %s", err.Error())
				}
				assert.Nil(afterUpdate)
				assert.Nil(afterUpdateState)
				assert.Equal(0, updatedRows)
				err = db.TestVerifyOplog(t, rw, c.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			require.NotNil(afterUpdate)
			require.NotNil(afterUpdateState)
			switch tt.name {
			case "valid-no-op":
				assert.Equal(c.UpdateTime, afterUpdate.UpdateTime)
			default:
				assert.NotEqual(c.UpdateTime, afterUpdate.UpdateTime)
			}
			found, foundStates, err := repo.LookupConnection(context.Background(), c.PublicId)
			require.NoError(err)
			assert.Equal(afterUpdate, found)
			dbassrt := dbassert.New(t, rw)
			if tt.args.bytesUp == 0 {
				dbassrt.IsNull(found, "BytesUp")
			}
			if tt.args.bytesDown == 0 {
				dbassrt.IsNull(found, "BytesDown")
			}
			if tt.args.closedReason == "" {
				dbassrt.IsNull(found, "ClosedReason")
			}
			assert.Equal(tt.args.closedReason.String(), found.ClosedReason)
			assert.Equal(tt.args.bytesUp, found.BytesUp)
			assert.Equal(tt.args.bytesDown, found.BytesDown)

			err = db.TestVerifyOplog(t, rw, c.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)

			switch {
			case tt.args.closedReason != "":
				require.Equal(2, len(foundStates))
				// sorted by StartTime desc
				assert.Equal(StatusClosed.String(), foundStates[0].Status)
				assert.Equal(StatusConnected.String(), foundStates[1].Status)
			default:
				require.Equal(1, len(foundStates))
				assert.Equal(StatusConnected.String(), foundStates[0].Status)
			}
		})
	}

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
