package session

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/sdk/strutil"
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
			got, err := repo.ListConnectionsBySessionId(context.Background(), tt.args.searchForSessionId, tt.args.opt...)
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
		got, err := repo.ListConnectionsBySessionId(context.Background(), session.PublicId, WithOrderByCreateTime(db.AscendingOrderBy))
		require.NoError(err)
		assert.Equal(wantCnt, len(got))

		for i := 0; i < len(got)-1; i++ {
			first := got[i].CreateTime.Timestamp.AsTime()
			second := got[i+1].CreateTime.Timestamp.AsTime()
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
			wantErrMsg:      "session.(Repository).DeleteConnection: missing public id: parameter violation: error #100",
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
			wantErrMsg:      "db.LookupById: record not found",
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
				assert.True(errors.IsNotFoundError(err))
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

func TestRepository_CloseDeadConnectionsOnWorker(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	ctx := context.Background()
	numConns := 12

	// Create two "workers". One will remain untouched while the other "goes
	// away and comes back" (worker 2).
	worker1 := TestWorker(t, conn, wrapper, WithServerId("worker1"))
	worker2 := TestWorker(t, conn, wrapper, WithServerId("worker2"))

	// Create a few sessions on each, activate, and authorize a connection
	var connIds []string
	var worker2ConnIds []string
	for i := 0; i < numConns; i++ {
		serverId := worker1.PrivateId
		if i%2 == 0 {
			serverId = worker2.PrivateId
		}
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithServerId(serverId), WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, serverId, "worker", []byte("foo"))
		require.NoError(err)
		c, cs, _, err := repo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Len(cs, 1)
		require.Equal(StatusAuthorized, cs[0].Status)
		connIds = append(connIds, c.GetPublicId())
		if i%2 == 0 {
			worker2ConnIds = append(worker2ConnIds, c.GetPublicId())
		}
	}

	// Mark half of the connections connected and leave the others authorized.
	// This is just to ensure we have a spread when we test it out.
	for i, connId := range connIds {
		if i%2 == 0 {
			_, cs, err := repo.ConnectConnection(ctx, ConnectWith{
				ConnectionId:       connId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    22,
			})
			require.NoError(err)
			require.Len(cs, 2)
			var foundAuthorized, foundConnected bool
			for _, status := range cs {
				if status.Status == StatusAuthorized {
					foundAuthorized = true
				}
				if status.Status == StatusConnected {
					foundConnected = true
				}
			}
			require.True(foundAuthorized)
			require.True(foundConnected)
		}
	}

	// There is a 10 second delay to account for time for the connections to
	// transition
	time.Sleep(15 * time.Second)

	// Now, advertise only some of the connection IDs for worker 2. After,
	// all connection IDs for worker 1 should be showing as non-closed, and
	// the ones for worker 2 not advertised should be closed.
	shouldStayOpen := worker2ConnIds[0:2]
	count, err := repo.CloseDeadConnectionsOnWorker(ctx, worker2.GetPrivateId(), shouldStayOpen)
	require.NoError(err)
	assert.Equal(4, count)

	// For the ones we didn't specify, we expect those to now be closed. We
	// expect all others to be open.

	shouldBeClosed := worker2ConnIds[2:]
	var conns []*Connection
	require.NoError(repo.list(ctx, &conns, "", nil))
	for _, conn := range conns {
		_, states, err := repo.LookupConnection(ctx, conn.PublicId)
		require.NoError(err)
		var foundClosed bool
		for _, state := range states {
			if state.Status == StatusClosed {
				foundClosed = true
				break
			}
		}
		assert.True(foundClosed == strutil.StrListContains(shouldBeClosed, conn.PublicId))
	}

	// Now, advertise none of the connection IDs for worker 2. This is mainly to
	// test that handling the case where we do not include IDs works properly as
	// it changes the where clause.
	count, err = repo.CloseDeadConnectionsOnWorker(ctx, worker1.GetPrivateId(), nil)
	require.NoError(err)
	assert.Equal(6, count)

	// We now expect all but those blessed few to be closed
	conns = nil
	require.NoError(repo.list(ctx, &conns, "", nil))
	for _, conn := range conns {
		_, states, err := repo.LookupConnection(ctx, conn.PublicId)
		require.NoError(err)
		var foundClosed bool
		for _, state := range states {
			if state.Status == StatusClosed {
				foundClosed = true
				break
			}
		}
		assert.True(foundClosed != strutil.StrListContains(shouldStayOpen, conn.PublicId))
	}
}
