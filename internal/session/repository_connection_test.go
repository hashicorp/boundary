package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/store"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_ListConnection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms, WithLimit(testLimit))
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms, WithLimit(testLimit))
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
			db.TestDeleteWhere(t, conn, func() interface{} { i := AllocConnection(); return &i }(), "1=1")
			testConnections := []*Connection{}
			for i := 0; i < tt.createCnt; i++ {
				c := TestConnection(t, conn,
					session.PublicId,
					"127.0.0.1",
					22,
					"127.0.0.1",
					2222,
					"127.0.0.1",
				)
				testConnections = append(testConnections, c)
			}
			assert.Equal(tt.createCnt, len(testConnections))
			got, err := connRepo.ListConnectionsBySessionId(context.Background(), tt.args.searchForSessionId, tt.args.opt...)
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
		db.TestDeleteWhere(t, conn, func() interface{} { i := AllocConnection(); return &i }(), "1=1")
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestConnection(t, conn,
				session.PublicId,
				"127.0.0.1",
				22,
				"127.0.0.1",
				2222,
				"127.0.0.1",
			)
		}
		got, err := connRepo.ListConnectionsBySessionId(context.Background(), session.PublicId, WithOrderByCreateTime(db.AscendingOrderBy))
		require.NoError(err)
		assert.Equal(wantCnt, len(got))

		for i := 0; i < len(got)-1; i++ {
			first := got[i].CreateTime.Timestamp.AsTime()
			second := got[i+1].CreateTime.Timestamp.AsTime()
			assert.True(first.Before(second))
		}
	})
}

func TestRepository_ConnectConnection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	setupFn := func() ConnectWith {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		srv := TestWorker(t, conn, wrapper)
		tofu := TestTofu(t)
		_, _, err := repo.ActivateSession(context.Background(), s.PublicId, s.Version, srv.PrivateId, tofu)
		require.NoError(t, err)
		c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
		return ConnectWith{
			ConnectionId:       c.PublicId,
			ClientTcpAddress:   "127.0.0.1",
			ClientTcpPort:      22,
			EndpointTcpAddress: "127.0.0.1",
			EndpointTcpPort:    2222,
			UserClientIp:       "127.0.0.1",
		}
	}
	tests := []struct {
		name        string
		connectWith ConnectWith
		wantErr     bool
		wantIsError errors.Code
	}{
		{
			name:        "valid",
			connectWith: setupFn(),
		},
		{
			name: "empty-SessionId",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.ConnectionId = ""
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-ClientTcpAddress",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.ClientTcpAddress = ""
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-ClientTcpPort",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.ClientTcpPort = 0
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-EndpointTcpAddress",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.EndpointTcpAddress = ""
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-EndpointTcpPort",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.EndpointTcpPort = 0
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "empty-UserClientIp",
			connectWith: func() ConnectWith {
				cw := setupFn()
				cw.UserClientIp = ""
				return cw
			}(),
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			c, cs, err := connRepo.ConnectConnection(context.Background(), tt.connectWith)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantIsError), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			require.NotNil(c)
			require.NotNil(cs)
			assert.Equal(StatusConnected, cs[0].Status)
			gotConn, _, err := connRepo.LookupConnection(context.Background(), c.PublicId)
			require.NoError(err)
			assert.Equal(tt.connectWith.ClientTcpAddress, gotConn.ClientTcpAddress)
			assert.Equal(tt.connectWith.ClientTcpPort, gotConn.ClientTcpPort)
			assert.Equal(tt.connectWith.ClientTcpAddress, gotConn.ClientTcpAddress)
			assert.Equal(tt.connectWith.EndpointTcpAddress, gotConn.EndpointTcpAddress)
			assert.Equal(tt.connectWith.EndpointTcpPort, gotConn.EndpointTcpPort)
			assert.Equal(tt.connectWith.UserClientIp, gotConn.UserClientIp)
		})
	}
}

func TestRepository_DeleteConnection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
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
				connection: TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1"),
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
			wantErrMsg:      "session.(ConnectionRepository).DeleteConnection: missing public id: parameter violation: error #100",
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
			deletedRows, err := connRepo.DeleteConnection(context.Background(), tt.args.connection.PublicId, tt.args.opt...)
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
			found, _, err := connRepo.LookupConnection(context.Background(), tt.args.connection.PublicId)
			assert.NoError(err)
			assert.Nil(found)

			err = db.TestVerifyOplog(t, rw, tt.args.connection.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
		})
	}
}

func TestRepository_orphanedConnections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require, assert := require.New(t), assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms, WithWorkerStateDelay(0))
	require.NoError(err)
	numConns := 12

	// Create two "workers". One will remain untouched while the other "goes
	// away and comes back" (worker 2).
	worker1 := TestWorker(t, conn, wrapper, WithWorkerId("worker1"))
	worker2 := TestWorker(t, conn, wrapper, WithWorkerId("worker2"))

	// Create a few sessions on each, activate, and authorize a connection
	var connIds []string
	var worker1ConnIds []string
	var worker2ConnIds []string
	for i := 0; i < numConns; i++ {
		serverId := worker1.PrivateId
		if i%2 == 0 {
			serverId = worker2.PrivateId
		}
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithWorkerId(serverId), WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, serverId, []byte("foo"))
		require.NoError(err)
		c, cs, err := connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Len(cs, 1)
		require.Equal(StatusAuthorized, cs[0].Status)
		connIds = append(connIds, c.GetPublicId())
		if i%2 == 0 {
			worker2ConnIds = append(worker2ConnIds, c.GetPublicId())
		} else {
			worker1ConnIds = append(worker1ConnIds, c.GetPublicId())
		}
	}

	// Mark half of the connections connected and leave the others authorized.
	// This is just to ensure we have a spread when we test it out.
	for i, connId := range connIds {
		if i%2 == 0 {
			_, cs, err := connRepo.ConnectConnection(ctx, ConnectWith{
				ConnectionId:       connId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    22,
				UserClientIp:       "127.0.0.1",
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

	// Now, advertise only some of the connection IDs for worker 2. After,
	// all connection IDs for worker 1 should be showing as non-closed, and
	// the ones for worker 2 not advertised should be closed.
	shouldStayOpen := worker2ConnIds[0:2]
	found, err := connRepo.closeOrphanedConnections(ctx, worker2.GetPrivateId(), shouldStayOpen)
	require.NoError(err)
	fmt.Printf("shouldstate: %v\nfound: %v\n", shouldStayOpen, found)
	require.Equal(4, len(found))

	// For the ones we didn't specify, we expect those to now be closed. We
	// expect all others to be open.

	shouldBeFound := worker2ConnIds[2:]
	assert.ElementsMatch(found, shouldBeFound)

	// Now, advertise none of the connection IDs for worker 2. This is mainly to
	// test that handling the case where we do not include IDs works properly as
	// it changes the where clause.
	found, err = connRepo.closeOrphanedConnections(ctx, worker1.GetPrivateId(), nil)
	require.NoError(err)
	assert.Equal(6, len(found))
	assert.ElementsMatch(found, worker1ConnIds)
}

func TestRepository_CloseConnectionsForDeadWorkers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	deadWorkerConnCloseMinGrace := 15 * time.Second
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(err)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)

	// connection count = 6 * states(authorized, connected, closed = 3) * servers_with_open_connections(3)
	numConns := 54

	// Create four "workers". This is similar to the setup in
	// TestRepository_CloseDeadConnectionsOnWorker, but a bit more complex;
	// firstly, the last worker will have no connections at all, and we will be
	// closing the others in stages to test multiple servers being closed at
	// once.
	worker1 := TestWorker(t, conn, wrapper, WithWorkerId("worker1"))
	worker2 := TestWorker(t, conn, wrapper, WithWorkerId("worker2"))
	worker3 := TestWorker(t, conn, wrapper, WithWorkerId("worker3"))
	worker4 := TestWorker(t, conn, wrapper, WithWorkerId("worker4"))

	// Create sessions on the first three, activate, and authorize connections
	var worker1ConnIds, worker2ConnIds, worker3ConnIds []string
	for i := 0; i < numConns; i++ {
		var serverId string
		if i%3 == 0 {
			serverId = worker1.PrivateId
		} else if i%3 == 1 {
			serverId = worker2.PrivateId
		} else {
			serverId = worker3.PrivateId
		}
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithWorkerId(serverId), WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, serverId, []byte("foo"))
		require.NoError(err)
		c, cs, err := connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Len(cs, 1)
		require.Equal(StatusAuthorized, cs[0].Status)
		if i%3 == 0 {
			worker1ConnIds = append(worker1ConnIds, c.GetPublicId())
		} else if i%3 == 1 {
			worker2ConnIds = append(worker2ConnIds, c.GetPublicId())
		} else {
			worker3ConnIds = append(worker3ConnIds, c.GetPublicId())
		}
	}

	// Mark a third of the connections connected, a third closed, and leave the
	// others authorized. This is just to ensure we have a spread when we test it
	// out.
	for i, connId := range func() []string {
		var s []string
		s = append(s, worker1ConnIds...)
		s = append(s, worker2ConnIds...)
		s = append(s, worker3ConnIds...)
		return s
	}() {
		if i%3 == 0 {
			_, cs, err := connRepo.ConnectConnection(ctx, ConnectWith{
				ConnectionId:       connId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    22,
				UserClientIp:       "127.0.0.1",
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
		} else if i%3 == 1 {
			resp, err := connRepo.closeConnections(ctx, []CloseWith{
				{
					ConnectionId: connId,
					ClosedReason: ConnectionCanceled,
				},
			})
			require.NoError(err)
			require.Len(resp, 1)
			cs := resp[0].ConnectionStates
			require.Len(cs, 2)
			var foundAuthorized, foundClosed bool
			for _, status := range cs {
				if status.Status == StatusAuthorized {
					foundAuthorized = true
				}
				if status.Status == StatusClosed {
					foundClosed = true
				}
			}
			require.True(foundAuthorized)
			require.True(foundClosed)
		}
	}

	// updateWorker is a helper for updating the update time for our
	// servers. The controller is read back so that we can reference
	// the most up-to-date fields.
	updateWorker := func(t *testing.T, w *store.Worker) *store.Worker {
		t.Helper()
		_, rowsUpdated, err := serversRepo.UpsertWorker(ctx, w)
		require.NoError(err)
		require.Equal(1, rowsUpdated)
		servers, err := serversRepo.ListWorkers(ctx)
		require.NoError(err)
		for _, server := range servers {
			if server.PrivateId == w.PrivateId {
				return server
			}
		}

		require.FailNowf("server %q not found after updating", w.PrivateId)
		// Looks weird but needed to build, as we fail in testify instead
		// of returning an error
		return nil
	}

	// requireConnectionStatus is a helper expecting all connections on a worker
	// to be closed.
	requireConnectionStatus := func(t *testing.T, connIds []string, expectAllClosed bool) {
		t.Helper()

		var conns []*Connection
		require.NoError(repo.list(ctx, &conns, "", nil))
		for i, connId := range connIds {
			var expected ConnectionStatus
			switch {
			case expectAllClosed:
				expected = StatusClosed

			case i%3 == 0:
				expected = StatusConnected

			case i%3 == 1:
				expected = StatusClosed

			case i%3 == 2:
				expected = StatusAuthorized
			}

			_, states, err := connRepo.LookupConnection(ctx, connId)
			require.NoError(err)
			require.Equal(expected, states[0].Status, "expected latest status for %q (index %d) to be %v", connId, i, expected)
		}
	}

	// We need this helper to fix the zone on protobuf timestamps
	// versus what gets reported in the
	// CloseConnectionsForDeadWorkersResult.
	timestampPbAsUTC := func(t *testing.T, tm time.Time) time.Time {
		t.Helper()
		// utcLoc, err := time.LoadLocation("Etc/UTC")
		// require.NoError(err)
		return tm.In(time.Local)
	}

	// Now try some scenarios.
	{
		// First, test the error/validation case.
		result, err := connRepo.CloseConnectionsForDeadWorkers(ctx, -1)
		require.Equal(err, errors.E(ctx,
			errors.WithCode(errors.InvalidParameter),
			errors.WithOp("session.(ConnectionRepository).CloseConnectionsForDeadWorkers"),
			errors.WithMsg(fmt.Sprintf("gracePeriod must be at least %s", deadWorkerConnCloseMinGrace)),
		))
		require.Nil(result)
	}

	{
		// Now, try the basis, or where all workers are reporting in.
		worker1 = updateWorker(t, worker1)
		worker2 = updateWorker(t, worker2)
		worker3 = updateWorker(t, worker3)
		updateWorker(t, worker4) // no re-assignment here because we never reference the server again

		result, err := connRepo.CloseConnectionsForDeadWorkers(ctx, deadWorkerConnCloseMinGrace)
		require.NoError(err)
		require.Empty(result)
		// Expect appropriate split connection state on worker1
		requireConnectionStatus(t, worker1ConnIds, false)
		// Expect appropriate split connection state on worker2
		requireConnectionStatus(t, worker2ConnIds, false)
		// Expect appropriate split connection state on worker3
		requireConnectionStatus(t, worker3ConnIds, false)
	}

	{
		// Now try a zero case - similar to the basis, but only in that no results
		// are expected to be returned for workers with no connections, even if
		// they are dead. Here, the server with no connections is worker #4.
		time.Sleep(deadWorkerConnCloseMinGrace)
		worker1 = updateWorker(t, worker1)
		worker2 = updateWorker(t, worker2)
		worker3 = updateWorker(t, worker3)

		result, err := connRepo.CloseConnectionsForDeadWorkers(ctx, deadWorkerConnCloseMinGrace)
		require.NoError(err)
		require.Empty(result)
		// Expect appropriate split connection state on worker1
		requireConnectionStatus(t, worker1ConnIds, false)
		// Expect appropriate split connection state on worker2
		requireConnectionStatus(t, worker2ConnIds, false)
		// Expect appropriate split connection state on worker3
		requireConnectionStatus(t, worker3ConnIds, false)
	}

	{
		// The first induction is letting the first worker "die" by not updating it
		// too. All of its authorized and connected connections should be dead.
		time.Sleep(deadWorkerConnCloseMinGrace)
		worker2 = updateWorker(t, worker2)
		worker3 = updateWorker(t, worker3)

		result, err := connRepo.CloseConnectionsForDeadWorkers(ctx, deadWorkerConnCloseMinGrace)
		require.NoError(err)
		// Assert that we have one result with the appropriate ID and
		// number of connections closed. Due to how things are
		require.Equal([]CloseConnectionsForDeadWorkersResult{
			{
				WorkerId:                worker1.PrivateId,
				LastUpdateTime:          timestampPbAsUTC(t, worker1.UpdateTime.AsTime()),
				NumberConnectionsClosed: 12, // 18 per server, with 6 closed already
			},
		}, result)
		// Expect all connections closed on worker1
		requireConnectionStatus(t, worker1ConnIds, true)
		// Expect appropriate split connection state on worker2
		requireConnectionStatus(t, worker2ConnIds, false)
		// Expect appropriate split connection state on worker3
		requireConnectionStatus(t, worker3ConnIds, false)
	}

	{
		// The final case is having the other two workers die. After
		// this, we should have all connections closed with the
		// appropriate message from the next two servers acted on.
		time.Sleep(deadWorkerConnCloseMinGrace)

		result, err := connRepo.CloseConnectionsForDeadWorkers(ctx, deadWorkerConnCloseMinGrace)
		require.NoError(err)
		// Assert that we have one result with the appropriate ID and number of connections closed.
		require.Equal([]CloseConnectionsForDeadWorkersResult{
			{
				WorkerId:                worker2.PrivateId,
				LastUpdateTime:          timestampPbAsUTC(t, worker2.UpdateTime.AsTime()),
				NumberConnectionsClosed: 12, // 18 per server, with 6 closed already
			},
			{
				WorkerId:                worker3.PrivateId,
				LastUpdateTime:          timestampPbAsUTC(t, worker3.UpdateTime.AsTime()),
				NumberConnectionsClosed: 12, // 18 per server, with 6 closed already
			},
		}, result)
		// Expect all connections closed on worker1
		requireConnectionStatus(t, worker1ConnIds, true)
		// Expect all connections closed on worker2
		requireConnectionStatus(t, worker2ConnIds, true)
		// Expect all connections closed on worker3
		requireConnectionStatus(t, worker3ConnIds, true)
	}
}

func TestRepository_CloseConnections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	setupFn := func(cnt int) []CloseWith {
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		srv := TestWorker(t, conn, wrapper)
		tofu := TestTofu(t)
		s, _, err := repo.ActivateSession(context.Background(), s.PublicId, s.Version, srv.PrivateId, tofu)
		require.NoError(t, err)
		cw := make([]CloseWith, 0, cnt)
		for i := 0; i < cnt; i++ {
			c := TestConnection(t, conn, s.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222, "127.0.0.1")
			require.NoError(t, err)
			cw = append(cw, CloseWith{
				ConnectionId: c.PublicId,
				BytesUp:      1,
				BytesDown:    2,
				ClosedReason: ConnectionClosedByUser,
			})
		}
		return cw
	}
	tests := []struct {
		name        string
		closeWith   []CloseWith
		reason      TerminationReason
		wantErr     bool
		wantIsError errors.Code
	}{
		{
			name:      "valid",
			closeWith: setupFn(2),
			reason:    ClosedByUser,
		},
		{
			name:        "empty-closed-with",
			closeWith:   []CloseWith{},
			reason:      ClosedByUser,
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
		{
			name: "missing-ConnectionId",
			closeWith: func() []CloseWith {
				cw := setupFn(2)
				cw[1].ConnectionId = ""
				return cw
			}(),
			reason:      ClosedByUser,
			wantErr:     true,
			wantIsError: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			resp, err := connRepo.closeConnections(context.Background(), tt.closeWith)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantIsError), err), "unexpected error %s", err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(len(tt.closeWith), len(resp))
			for _, r := range resp {
				require.NotNil(r.Connection)
				require.NotNil(r.ConnectionStates)
				assert.Equal(StatusClosed, r.ConnectionStates[0].Status)
			}
		})
	}
}
