package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assert the interface
var _ = scheduler.Job(new(sessionCleanupJob))

// This test has been largely adapted from
// TestRepository_CloseDeadConnectionsOnWorker in
// internal/session/repository_connection_test.go.
func TestSessionCleanupJob(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)
	sessionRepo, err := session.NewRepository(rw, rw, kms)
	require.NoError(err)
	ctx := context.Background()
	numConns := 12

	// Create two "workers". One will remain untouched while the other "goes
	// away and comes back" (worker 2).
	worker1 := session.TestWorker(t, conn, wrapper, session.WithServerId("worker1"))
	worker2 := session.TestWorker(t, conn, wrapper, session.WithServerId("worker2"))

	// Create a few sessions on each, activate, and authorize a connection
	var connIds []string
	connIdsByWorker := make(map[string][]string)
	for i := 0; i < numConns; i++ {
		serverId := worker1.PrivateId
		if i%2 == 0 {
			serverId = worker2.PrivateId
		}
		sess := session.TestDefaultSession(t, conn, wrapper, iamRepo, session.WithServerId(serverId), session.WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = sessionRepo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, serverId, "worker", []byte("foo"))
		require.NoError(err)
		c, cs, _, err := sessionRepo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Len(cs, 1)
		require.Equal(session.StatusAuthorized, cs[0].Status)
		connIds = append(connIds, c.GetPublicId())
		if i%2 == 0 {
			connIdsByWorker[worker2.PrivateId] = append(connIdsByWorker[worker2.PrivateId], c.GetPublicId())
		} else {
			connIdsByWorker[worker1.PrivateId] = append(connIdsByWorker[worker1.PrivateId], c.GetPublicId())
		}
	}

	// Mark half of the connections connected and leave the others authorized.
	// This is just to ensure we have a spread when we test it out.
	for i, connId := range connIds {
		if i%2 == 0 {
			_, cs, err := sessionRepo.ConnectConnection(ctx, session.ConnectWith{
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
				if status.Status == session.StatusAuthorized {
					foundAuthorized = true
				}
				if status.Status == session.StatusConnected {
					foundConnected = true
				}
			}
			require.True(foundAuthorized)
			require.True(foundConnected)
		}
	}

	// Create the job.
	job, err := newSessionCleanupJob(
		hclog.New(&hclog.LoggerOptions{Level: hclog.Trace}),
		func() (*session.Repository, error) { return sessionRepo, nil },
		session.DeadWorkerConnCloseMinGrace,
	)
	require.NoError(err)

	// sleep the status grace period.
	time.Sleep(time.Second * time.Duration(session.DeadWorkerConnCloseMinGrace))

	// Push an upsert to the first worker so that its status has been
	// updated.
	_, rowsUpdated, err := serversRepo.UpsertServer(ctx, worker1, []servers.Option{}...)
	require.NoError(err)
	require.Equal(1, rowsUpdated)

	// Run the job.
	require.NoError(job.Run(ctx))

	// Assert connection state on both workers.
	assertConnections := func(workerId string, closed bool) {
		connIds, ok := connIdsByWorker[workerId]
		require.True(ok)
		require.Len(connIds, 6)
		for _, connId := range connIds {
			_, states, err := sessionRepo.LookupConnection(ctx, connId, nil)
			require.NoError(err)
			var foundClosed bool
			for _, state := range states {
				if state.Status == session.StatusClosed {
					foundClosed = true
					break
				}
			}
			assert.Equal(closed, foundClosed)
		}
	}

	// Assert that all connections on the second worker are closed
	assertConnections(worker2.PrivateId, true)
	// Assert that all connections on the first worker are still open
	assertConnections(worker1.PrivateId, false)
}

func TestSessionCleanupJobNewJobErr(t *testing.T) {
	t.Parallel()
	const op = "controller.newNewSessionCleanupJob"
	require := require.New(t)

	job, err := newSessionCleanupJob(nil, nil, 0)
	require.Equal(err, errors.E(
		errors.WithCode(errors.InvalidParameter),
		errors.WithOp(op),
		errors.WithMsg("missing logger"),
	))
	require.Nil(job)

	job, err = newSessionCleanupJob(hclog.New(nil), nil, 0)
	require.Equal(err, errors.E(
		errors.WithCode(errors.InvalidParameter),
		errors.WithOp(op),
		errors.WithMsg("missing sessionRepoFn"),
	))
	require.Nil(job)

	job, err = newSessionCleanupJob(hclog.New(nil), func() (*session.Repository, error) { return nil, nil }, 0)
	require.Equal(err, errors.E(
		errors.WithCode(errors.InvalidParameter),
		errors.WithOp(op),
		errors.WithMsg(fmt.Sprintf("invalid gracePeriod, must be greater than %d", session.DeadWorkerConnCloseMinGrace)),
	))
	require.Nil(job)
}
