// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assert the interface
var _ = scheduler.Job(new(sessionConnectionCleanupJob))

// This test has been largely adapted from
// TestRepository_CloseDeadConnectionsOnWorker in
// internal/session/repository_connection_test.go.
func TestSessionConnectionCleanupJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	gracePeriod := new(atomic.Int64)
	gracePeriod.Store(int64(time.Second))

	require, assert := require.New(t), assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	sessionRepo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	connectionRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(err)

	numConns := 12

	// Create two "workers". One will remain untouched while the other "goes
	// away and comes back" (worker 2).
	worker1 := server.TestKmsWorker(t, conn, wrapper)
	worker2 := server.TestKmsWorker(t, conn, wrapper)

	updateServer := func(t *testing.T, w *server.Worker) *server.Worker {
		t.Helper()
		pubId := w.GetPublicId()
		w.PublicId = ""
		wkr, err := server.TestUpsertAndReturnWorker(ctx, t, w, serversRepo, server.WithPublicId(pubId))
		require.NoError(err)
		err = serversRepo.UpsertSessionInfo(ctx, pubId)
		require.NoError(err)
		return wkr
	}
	worker1 = updateServer(t, worker1)
	worker2 = updateServer(t, worker2)

	// Create a few sessions on each, activate, and authorize a connection
	var connIds []string
	connIdsByWorker := make(map[string][]string)
	for i := 0; i < numConns; i++ {
		serverId := worker1.PublicId
		if i%2 == 0 {
			serverId = worker2.PublicId
		}
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = sessionRepo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, []byte("foo"))
		require.NoError(err)
		c, _, err := AuthorizeConnection(ctx, sessionRepo, connectionRepo, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Equal(StatusAuthorized, ConnectionStatusFromString(c.Status))
		connIds = append(connIds, c.GetPublicId())
		if i%2 == 0 {
			connIdsByWorker[worker2.PublicId] = append(connIdsByWorker[worker2.PublicId], c.GetPublicId())
		} else {
			connIdsByWorker[worker1.PublicId] = append(connIdsByWorker[worker1.PublicId], c.GetPublicId())
		}
	}

	// Mark half of the connections connected and leave the others authorized.
	// This is just to ensure we have a spread when we test it out.
	for i, connId := range connIds {
		if i%2 == 0 {
			cc, err := connectionRepo.ConnectConnection(ctx, ConnectWith{
				ConnectionId:       connId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    22,
				UserClientIp:       "127.0.0.1",
			})
			require.NoError(err)
			require.Equal(StatusConnected, ConnectionStatusFromString(cc.Status))
		}
	}

	// Create the job.
	job, err := newSessionConnectionCleanupJob(ctx, rw, gracePeriod)
	job.workerRPCGracePeriod = gracePeriod // by-pass factory assert so we dont have to wait so long
	require.NoError(err)

	// sleep the status grace period.
	time.Sleep(time.Duration(gracePeriod.Load()))

	// Push an upsert to the first worker so that its status has been
	// updated.
	worker1 = updateServer(t, worker1)

	// Run the job.
	require.NoError(job.Run(ctx, 0))

	// Assert connection state on both workers.
	assertConnections := func(workerId string, closed bool) {
		connIds, ok := connIdsByWorker[workerId]
		require.True(ok)
		require.Len(connIds, 6)
		for _, connId := range connIds {
			conn, err := connectionRepo.LookupConnection(ctx, connId)
			require.NoError(err)
			var foundClosed bool
			if ConnectionStatusFromString(conn.Status) == StatusClosed {
				foundClosed = true
			}
			assert.Equal(closed, foundClosed)
		}
	}

	// Assert that all connections on the second worker are closed
	assertConnections(worker2.PublicId, true)
	// Assert that all connections on the first worker are still open
	assertConnections(worker1.PublicId, false)
}

func TestSessionConnectionCleanupJobNewJobErr(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const op = "session.newNewSessionConnectionCleanupJob"
	require := require.New(t)

	grace := new(atomic.Int64)
	grace.Store(1000000)

	job, err := newSessionConnectionCleanupJob(ctx, nil, grace)
	require.Equal(err, errors.E(
		ctx,
		errors.WithCode(errors.InvalidParameter),
		errors.WithOp(op),
		errors.WithMsg("missing db writer"),
	))
	require.Nil(job)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	job, err = newSessionConnectionCleanupJob(ctx, rw, nil)
	require.Equal(err, errors.E(
		ctx,
		errors.WithCode(errors.InvalidParameter),
		errors.WithOp(op),
		errors.WithMsg(fmt.Sprintf("missing grace period")),
	))
	require.Nil(job)

	job, err = newSessionConnectionCleanupJob(ctx, rw, new(atomic.Int64))
	require.Equal(err, errors.E(
		ctx,
		errors.WithCode(errors.InvalidParameter),
		errors.WithOp(op),
		errors.WithMsg(fmt.Sprintf("grace period is zero")),
	))
	require.Nil(job)
}

func TestCloseConnectionsForDeadWorkers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	gracePeriod := 1 * time.Second
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(err)
	serversRepo, err := server.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)

	defaultLiveness := new(atomic.Int64)
	defaultLiveness.Store(int64(server.DefaultLiveness))

	job, err := newSessionConnectionCleanupJob(ctx, rw, defaultLiveness)
	require.NoError(err)

	// connection count = 6 * states(authorized, connected, closed = 3) * servers_with_open_connections(3)
	numConns := 54

	// Create four "workers". This is similar to the setup in
	// TestRepository_CloseDeadConnectionsOnWorker, but a bit more complex;
	// firstly, the last worker will have no connections at all, and we will be
	// closing the others in stages to test multiple servers being closed at
	// once.
	worker1 := server.TestKmsWorker(t, conn, wrapper)
	worker2 := server.TestKmsWorker(t, conn, wrapper)
	worker3 := server.TestKmsWorker(t, conn, wrapper)
	worker4 := server.TestKmsWorker(t, conn, wrapper)

	// Create sessions on the first three, activate, and authorize connections
	var worker1ConnIds, worker2ConnIds, worker3ConnIds []string
	for i := 0; i < numConns; i++ {
		var serverId string
		if i%3 == 0 {
			serverId = worker1.PublicId
		} else if i%3 == 1 {
			serverId = worker2.PublicId
		} else {
			serverId = worker3.PublicId
		}
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, []byte("foo"))
		require.NoError(err)
		c, err := connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Equal(StatusAuthorized, ConnectionStatusFromString(c.Status))
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
			cc, err := connRepo.ConnectConnection(ctx, ConnectWith{
				ConnectionId:       connId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    22,
				UserClientIp:       "127.0.0.1",
			})
			require.NoError(err)
			require.Equal(StatusConnected, ConnectionStatusFromString(cc.Status))
		} else if i%3 == 1 {
			resp, err := connRepo.closeConnections(ctx, []CloseWith{
				{
					ConnectionId: connId,
					ClosedReason: ConnectionCanceled,
				},
			})
			require.NoError(err)
			require.Len(resp, 1)
			cs := resp[0].ConnectionState
			require.Equal(StatusClosed, cs)
		}
	}

	// updateServer is a helper for updating the update time for our
	// servers. The controller is read back so that we can reference
	// the most up-to-date fields.
	updateServer := func(t *testing.T, w *server.Worker) *server.Worker {
		t.Helper()
		pubId := w.GetPublicId()
		w.PublicId = ""
		wkr, err := server.TestUpsertAndReturnWorker(ctx, t, w, serversRepo, server.WithPublicId(pubId))
		require.NoError(err)
		err = serversRepo.UpsertSessionInfo(ctx, pubId)
		require.NoError(err)
		return wkr
	}

	// requireConnectionStatus is a helper expecting all connections on a worker
	// to be closed.
	requireConnectionStatus := func(t *testing.T, connIds []string, expectAllClosed bool) {
		t.Helper()

		var conns []*Connection
		require.NoError(rw.SearchWhere(ctx, &conns, "", nil))
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

			conn, err := connRepo.LookupConnection(ctx, connId)
			require.NoError(err)
			require.Equal(expected, ConnectionStatusFromString(conn.Status), "expected latest status for %q (index %d) to be %v", connId, i, expected)
		}
	}

	// We need this helper to fix the zone on protobuf timestamps
	// versus what gets reported in the
	// closeConnectionsForDeadWorkersResult.
	timestampPbAsUTC := func(t *testing.T, tm time.Time) time.Time {
		t.Helper()
		// utcLoc, err := time.LoadLocation("Etc/UTC")
		// require.NoError(err)
		return tm.In(time.Local)
	}

	// Now try some scenarios.
	{
		// Now, try the basis, or where all workers are reporting in.
		worker1 = updateServer(t, worker1)
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)
		updateServer(t, worker4) // no re-assignment here because we never reference the server again

		result, err := job.closeConnectionsForDeadWorkers(ctx, gracePeriod)
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
		time.Sleep(gracePeriod)
		worker1 = updateServer(t, worker1)
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)

		result, err := job.closeConnectionsForDeadWorkers(ctx, gracePeriod)
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
		time.Sleep(gracePeriod)
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)

		result, err := job.closeConnectionsForDeadWorkers(ctx, gracePeriod)
		require.NoError(err)
		// Assert that we have one result with the appropriate ID and
		// number of connections closed. Due to how things are
		require.Len(result, 1)
		require.Equal(worker1.PublicId, result[0].WorkerId)
		require.Equal(12, result[0].NumberConnectionsClosed)
		require.WithinDuration(timestampPbAsUTC(t, worker1.GetLastStatusTime().AsTime()), result[0].LastUpdateTime, time.Second)

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
		time.Sleep(gracePeriod)

		result, err := job.closeConnectionsForDeadWorkers(ctx, gracePeriod)
		require.NoError(err)
		// Assert that we have one result with the appropriate ID and number of connections closed.
		expectedWorkers := map[string]*server.Worker{
			worker2.PublicId: worker2,
			worker3.PublicId: worker3,
		}
		require.Len(result, len(expectedWorkers))
		for _, r := range result {
			expectedWorker, ok := expectedWorkers[r.WorkerId]
			require.True(ok)
			require.Equal(expectedWorker.PublicId, r.WorkerId)
			require.Equal(12, r.NumberConnectionsClosed)
			require.WithinDuration(timestampPbAsUTC(t, expectedWorker.GetLastStatusTime().AsTime()), r.LastUpdateTime, time.Second)
		}

		// Expect all connections closed on worker1
		requireConnectionStatus(t, worker1ConnIds, true)
		// Expect all connections closed on worker2
		requireConnectionStatus(t, worker2ConnIds, true)
		// Expect all connections closed on worker3
		requireConnectionStatus(t, worker3ConnIds, true)
	}
}

func TestCloseWorkerlessConnections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(err)

	hourDuration := new(atomic.Int64)
	hourDuration.Store(int64(time.Hour))

	job, err := newSessionConnectionCleanupJob(ctx, rw, hourDuration)
	require.NoError(err)

	createConnection := func(workerId string) *Connection {
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, []byte("foo"))
		require.NoError(err)

		conn, err := connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), workerId)
		require.NoError(err)
		require.Equal(StatusAuthorized, ConnectionStatusFromString(conn.Status))
		return conn
	}

	// Setup deleted worker connections
	deletedWorker := server.TestKmsWorker(t, conn, wrapper)
	dActiveConn := createConnection(deletedWorker.GetPublicId())
	dClosedConn := createConnection(deletedWorker.GetPublicId())
	_, err = connRepo.closeConnections(ctx, []CloseWith{{
		ConnectionId: dClosedConn.PublicId,
		BytesUp:      1,
		BytesDown:    2,
		ClosedReason: ConnectionClosedByUser,
	}})
	require.NoError(err)
	_, err = rw.Delete(ctx, deletedWorker)
	require.NoError(err)

	// Non deleted worker case
	activeWorker := server.TestKmsWorker(t, conn, wrapper)
	activeConn := createConnection(activeWorker.GetPublicId())
	closedConn := createConnection(activeWorker.GetPublicId())
	_, err = connRepo.closeConnections(ctx, []CloseWith{{
		ConnectionId: closedConn.PublicId,
		BytesUp:      1,
		BytesDown:    2,
		ClosedReason: ConnectionClosedByUser,
	}})
	require.NoError(err)

	con, err := connRepo.LookupConnection(ctx, dActiveConn.GetPublicId())
	require.NoError(err)
	require.Equal(StatusAuthorized, ConnectionStatusFromString(con.Status))

	con, err = connRepo.LookupConnection(ctx, dClosedConn.GetPublicId())
	require.NoError(err)
	require.Equal(StatusClosed, ConnectionStatusFromString(con.Status))

	con, err = connRepo.LookupConnection(ctx, activeConn.GetPublicId())
	require.NoError(err)
	require.Equal(StatusAuthorized, ConnectionStatusFromString(con.Status))

	con, err = connRepo.LookupConnection(ctx, closedConn.GetPublicId())
	require.NoError(err)
	require.Equal(StatusClosed, ConnectionStatusFromString(con.Status))

	// Run the job
	numClosed, err := job.closeWorkerlessConnections(ctx)
	require.NoError(err)
	assert.Equal(t, 1, numClosed)

	// This is the only one that the job should have actually closed.
	con, err = connRepo.LookupConnection(ctx, dActiveConn.GetPublicId())
	require.NoError(err)
	require.Equal(StatusClosed, ConnectionStatusFromString(con.Status))

	con, err = connRepo.LookupConnection(ctx, dClosedConn.GetPublicId())
	require.NoError(err)
	require.Equal(StatusClosed, ConnectionStatusFromString(con.Status))

	con, err = connRepo.LookupConnection(ctx, activeConn.GetPublicId())
	require.NoError(err)
	require.Equal(StatusAuthorized, ConnectionStatusFromString(con.Status))

	con, err = connRepo.LookupConnection(ctx, closedConn.GetPublicId())
	require.NoError(err)
	require.Equal(StatusClosed, ConnectionStatusFromString(con.Status))
}
