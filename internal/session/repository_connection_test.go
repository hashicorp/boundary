package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/go-secure-stdlib/strutil"
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

	// There is a 10 second delay to account for time for the connections to
	// transition
	time.Sleep(15 * time.Second)

	// Now, advertise only some of the connection IDs for worker 2. After,
	// all connection IDs for worker 1 should be showing as non-closed, and
	// the ones for worker 2 not advertised should be closed.
	shouldStayOpen := worker2ConnIds[0:2]
	count, err := repo.CloseDeadConnectionsForWorker(ctx, worker2.GetPrivateId(), shouldStayOpen)
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
	count, err = repo.CloseDeadConnectionsForWorker(ctx, worker1.GetPrivateId(), nil)
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

func TestRepository_CloseConnectionsForDeadWorkers(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)
	ctx := context.Background()

	// connection count = 6 * states(authorized, connected, closed = 3) * servers_with_open_connections(3)
	numConns := 54

	// Create four "workers". This is similar to the setup in
	// TestRepository_CloseDeadConnectionsOnWorker, but a bit more complex;
	// firstly, the last worker will have no connections at all, and we will be
	// closing the others in stages to test multiple servers being closed at
	// once.
	worker1 := TestWorker(t, conn, wrapper, WithServerId("worker1"))
	worker2 := TestWorker(t, conn, wrapper, WithServerId("worker2"))
	worker3 := TestWorker(t, conn, wrapper, WithServerId("worker3"))
	worker4 := TestWorker(t, conn, wrapper, WithServerId("worker4"))

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
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithServerId(serverId), WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, serverId, "worker", []byte("foo"))
		require.NoError(err)
		c, cs, _, err := repo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
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
			_, cs, err := repo.ConnectConnection(ctx, ConnectWith{
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
			resp, err := repo.CloseConnections(ctx, []CloseWith{
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

	// There is a 15 second delay to account for time for the connections to
	// transition
	time.Sleep(15 * time.Second)

	// updateServer is a helper for updating the update time for our
	// servers. The controller is read back so that we can reference
	// the most up-to-date fields.
	updateServer := func(t *testing.T, w *servers.Server) *servers.Server {
		t.Helper()
		_, rowsUpdated, err := serversRepo.UpsertServer(ctx, w)
		require.NoError(err)
		require.Equal(1, rowsUpdated)
		servers, err := serversRepo.ListServers(ctx, servers.ServerTypeWorker)
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

			_, states, err := repo.LookupConnection(ctx, connId)
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
		result, err := repo.CloseConnectionsForDeadWorkers(ctx, 0)
		require.Equal(err, errors.E(ctx,
			errors.WithCode(errors.InvalidParameter),
			errors.WithOp("session.(Repository).CloseConnectionsForDeadWorkers"),
			errors.WithMsg(fmt.Sprintf("gracePeriod must be at least %d seconds", DeadWorkerConnCloseMinGrace)),
		))
		require.Nil(result)
	}

	{
		// Now, try the basis, or where all workers are reporting in.
		worker1 = updateServer(t, worker1)
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)
		updateServer(t, worker4) // no re-assignment here because we never reference the server again

		result, err := repo.CloseConnectionsForDeadWorkers(ctx, DeadWorkerConnCloseMinGrace)
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
		time.Sleep(time.Second * time.Duration(DeadWorkerConnCloseMinGrace))
		worker1 = updateServer(t, worker1)
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)

		result, err := repo.CloseConnectionsForDeadWorkers(ctx, DeadWorkerConnCloseMinGrace)
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
		time.Sleep(time.Second * time.Duration(DeadWorkerConnCloseMinGrace))
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)

		result, err := repo.CloseConnectionsForDeadWorkers(ctx, DeadWorkerConnCloseMinGrace)
		require.NoError(err)
		// Assert that we have one result with the appropriate ID and
		// number of connections closed. Due to how things are
		require.Equal([]CloseConnectionsForDeadWorkersResult{
			{
				ServerId:                worker1.PrivateId,
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
		time.Sleep(time.Second * time.Duration(DeadWorkerConnCloseMinGrace))

		result, err := repo.CloseConnectionsForDeadWorkers(ctx, DeadWorkerConnCloseMinGrace)
		require.NoError(err)
		// Assert that we have one result with the appropriate ID and number of connections closed.
		require.Equal([]CloseConnectionsForDeadWorkersResult{
			{
				ServerId:                worker2.PrivateId,
				LastUpdateTime:          timestampPbAsUTC(t, worker2.UpdateTime.AsTime()),
				NumberConnectionsClosed: 12, // 18 per server, with 6 closed already
			},
			{
				ServerId:                worker3.PrivateId,
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

func TestRepository_ShouldCloseConnectionsOnWorker(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	ctx := context.Background()
	numConns := 12

	// Create a worker, we only need one here as our query is dependent
	// on connection and not worker.
	worker1 := TestWorker(t, conn, wrapper, WithServerId("worker1"))

	// Create a few sessions on each, activate, and authorize a connection
	var connIds []string
	sessionConnIds := make(map[string][]string)
	for i := 0; i < numConns; i++ {
		serverId := worker1.PrivateId
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithServerId(serverId), WithDbOpts(db.WithSkipVetForWrite(true)))
		sessionId := sess.GetPublicId()
		sess, _, err = repo.ActivateSession(ctx, sessionId, sess.Version, serverId, "worker", []byte("foo"))
		require.NoError(err)
		c, cs, _, err := repo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Len(cs, 1)
		require.Equal(StatusAuthorized, cs[0].Status)
		connId := c.GetPublicId()
		connIds = append(connIds, connId)
		sessionConnIds[sessionId] = append(sessionConnIds[sessionId], connId)
	}

	// Mark half of the connections connected, close the other half.
	for i, connId := range connIds {
		if i%2 == 0 {
			_, cs, err := repo.ConnectConnection(ctx, ConnectWith{
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
		} else {
			resp, err := repo.CloseConnections(ctx, []CloseWith{
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

	// There is a 10 second delay to account for time for the connections to
	// transition
	time.Sleep(15 * time.Second)

	// Now we try some scenarios.
	{
		// First test an empty set.
		result, err := repo.ShouldCloseConnectionsOnWorker(ctx, nil, nil)
		require.NoError(err)
		require.Zero(result, "should be empty when no connections are supplied")
	}

	{
		// Here we pass in all of our connections without a filter on
		// session. This should return half of the connections - the ones
		// that we marked as closed.
		//
		// Create a copy of our session map with the sessions that have
		// closed connections taken out.
		expectedSessionConnIds := make(map[string][]string)
		for sessionId, connIds := range sessionConnIds {
			for _, connId := range connIds {
				if testIsConnectionClosed(ctx, t, repo, connId) {
					expectedSessionConnIds[sessionId] = append(expectedSessionConnIds[sessionId], connId)
				}
			}
		}

		// Send query, use all connections w/o a filter on sessions.
		actualSessionConnIds, err := repo.ShouldCloseConnectionsOnWorker(ctx, connIds, nil)
		require.NoError(err)
		require.Equal(expectedSessionConnIds, actualSessionConnIds)
	}

	{
		// Finally, add a session filter. We do this by just alternating
		// the session IDs we want to filter on.
		expectedSessionConnIds := make(map[string][]string)
		var filterSessionIds []string
		var filterSession bool
		for sessionId, connIds := range sessionConnIds {
			for _, connId := range connIds {
				if testIsConnectionClosed(ctx, t, repo, connId) {
					if !filterSession {
						expectedSessionConnIds[sessionId] = append(expectedSessionConnIds[sessionId], connId)
					} else {
						filterSessionIds = append(filterSessionIds, sessionId)
					}

					// Toggle filterSession here (instead of just outer session
					// loop) so that we aren't just lining up on
					// connected/disconnected connections.
					filterSession = !filterSession
				}
			}
		}

		// Send query with the session filter.
		actualSessionConnIds, err := repo.ShouldCloseConnectionsOnWorker(ctx, connIds, filterSessionIds)
		require.NoError(err)
		require.Equal(expectedSessionConnIds, actualSessionConnIds)
	}
}

func testIsConnectionClosed(ctx context.Context, t *testing.T, repo *Repository, connId string) bool {
	require := require.New(t)
	_, states, err := repo.LookupConnection(ctx, connId)
	require.NoError(err)
	// Use first state as this LookupConnections returns ordered by
	// start time, descending.
	return states[0].Status == StatusClosed
}
