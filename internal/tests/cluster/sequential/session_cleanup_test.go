// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sequential

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/dawdle"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

// timeoutBurdenType details our "burden cases" for the session
// cleanup tests.
//
// There are 3 burden cases:
//
// * default: This case simulates normal default operation where both
// worker and controller generally are timing out connections at
// generally the same interval. In reality, this is not necessarily
// going to be the case, but it's hard to test individual cases when
// both settings are the same.
//
// * worker: This case assumes the worker is the source of truth for
// controller state. Here, the controller's grace period is
// increased to a high factor over the default to ensure that the
// worker is managing the lifecycle of a connection and will properly
// unclaim it closed once the connection resumes, ensuring the
// connection is marked as closed on the worker.
type timeoutBurdenType string

const (
	timeoutBurdenTypeDefault timeoutBurdenType = "default"
	timeoutBurdenTypeWorker  timeoutBurdenType = "worker"
)

var timeoutBurdenCases = []timeoutBurdenType{timeoutBurdenTypeDefault, timeoutBurdenTypeWorker}

func controllerGracePeriod(ty timeoutBurdenType) time.Duration {
	if ty == timeoutBurdenTypeWorker {
		return helper.DefaultControllerRPCGracePeriod * 10
	}

	return helper.DefaultControllerRPCGracePeriod
}

// TestSessionCleanup is the main test for session cleanup, and
// dispatches to the individual subtests.
func TestSessionCleanup(t *testing.T) {
	t.Run("default/single_controller", testWorkerSessionCleanupSingle("default"))
	t.Run("default/multi_controller", testWorkerSessionCleanupMulti("default"))
	t.Run("worker/single_controller", testWorkerSessionCleanupSingle("worker"))
	t.Run("worker/multi_controller", testWorkerSessionCleanupMulti("worker"))
}

func testWorkerSessionCleanupSingle(burdenCase timeoutBurdenType) func(t *testing.T) {
	const op = "cluster.testWorkerSessionCleanupSingle"
	return func(t *testing.T) {
		require := require.New(t)
		// This prevents us from running tests in parallel.
		server.TestUseCommunityFilterWorkersFn(t)
		logger := hclog.New(&hclog.LoggerOptions{
			Name:  t.Name(),
			Level: hclog.Trace,
		})

		conf, err := config.DevController()
		require.NoError(err)

		pl, err := net.Listen("tcp", "[::1]:0")
		require.NoError(err)
		c1 := controller.NewTestController(t, &controller.TestControllerOpts{
			Config:                 conf,
			InitialResourcesSuffix: "1234567890",
			Logger:                 logger.Named("c1"),
			PublicClusterAddr:      pl.Addr().String(),
			WorkerRPCGracePeriod:   controllerGracePeriod(burdenCase),
			// Run the scheduler more often to speed up cleanup of orphaned connections
			SchedulerRunJobInterval: 500 * time.Millisecond,
		})

		helper.ExpectWorkers(t, c1)

		// Wire up the testing proxies
		require.Len(c1.ClusterAddrs(), 1)
		proxy, err := dawdle.NewProxy("tcp", "", c1.ClusterAddrs()[0],
			dawdle.WithListener(pl),
			dawdle.WithRbufSize(256),
			dawdle.WithWbufSize(256),
		)
		require.NoError(err)
		t.Cleanup(func() {
			_ = proxy.Close()
		})
		require.NotEmpty(t, proxy.ListenerAddr())

		w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
			WorkerAuthKms:    c1.Config().WorkerAuthKms,
			InitialUpstreams: []string{proxy.ListenerAddr()},
			Logger:           logger.Named("w1"),
			SuccessfulControllerRPCGracePeriodDuration: helper.DefaultControllerRPCGracePeriod,
			WorkerRPCInterval:                          time.Second,
		})

		helper.ExpectWorkers(t, c1, w1)

		// Use an independent context for test things that take a context so
		// that we aren't tied to any timeouts in the controller, etc. This
		// can interfere with some of the test operations.
		ctx := context.Background()

		// Connect target
		client := c1.Client()
		client.SetToken(c1.Token().Token)
		tcl := targets.NewClient(client)
		tgt, err := tcl.Read(ctx, "ttcp_1234567890")
		require.NoError(err)
		require.NotNil(tgt)

		// Create test server, update default port on target
		ts := helper.NewTestTcpServer(t)
		require.NotNil(t, ts)
		t.Cleanup(ts.Close)
		tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(-1))
		require.NoError(err)
		require.NotNil(tgt)

		// Authorize and connect
		sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890")
		sConn := sess.Connect(ctx, t)

		// Run initial send/receive test, make sure things are working
		t.Log("running initial send/recv test")
		sConn.TestSendRecvAll(t)

		// Wait for a session info to be sent to the server, so the controller has
		// at least one record of the connection.
		w1.Worker().TestWaitForNextSuccessfulSessionInfoUpdate(t)

		// Kill the link
		t.Log("pausing controller/worker link")
		proxy.Pause()

		// Wait for failure connection state (depends on burden case)
		switch burdenCase {
		case timeoutBurdenTypeWorker:
			// Wait on worker, then check controller
			sess.ExpectConnectionStateOnWorker(ctx, t, w1, session.StatusClosed)
			sess.ExpectConnectionStateOnController(ctx, t, c1.Controller().ConnectionRepoFn, session.StatusConnected)

		default:
			// Should be closed on both worker and controller. Wait on
			// worker then check controller.
			sess.ExpectConnectionStateOnWorker(ctx, t, w1, session.StatusClosed)
			sess.ExpectConnectionStateOnController(ctx, t, c1.Controller().ConnectionRepoFn, session.StatusClosed)
		}

		sConn.TestSendRecvFail(t)

		// Resume the connection, and reconnect.
		t.Log("resuming controller/worker link")
		proxy.Resume()
		helper.ExpectWorkers(t, c1, w1)

		// Do something post-reconnect depending on burden case. Note in
		// the default case, both worker and controller should be
		// relatively in sync, so we don't worry about these
		// post-reconnection assertions.
		switch burdenCase {
		case timeoutBurdenTypeWorker:
			// If we are expecting the worker to be the source of truth of
			// a connection status, ensure that our old session's
			// connections are actually closed now that the worker is
			// properly reporting in again.
			sess.ExpectConnectionStateOnController(ctx, t, c1.Controller().ConnectionRepoFn, session.StatusClosed)
		}

		// Proceed with new connection test
		t.Log("connecting to new session after resuming controller/worker link")
		sess = helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890") // re-assign, other connection will close in t.Cleanup()
		sConn = sess.Connect(ctx, t)
		sConn.TestSendRecvAll(t)
	}
}

func testWorkerSessionCleanupMulti(burdenCase timeoutBurdenType) func(t *testing.T) {
	const op = "cluster.testWorkerSessionCleanupMulti"
	return func(t *testing.T) {
		// This prevents us from running tests in parallel.
		server.TestUseCommunityFilterWorkersFn(t)
		require := require.New(t)
		logger := hclog.New(&hclog.LoggerOptions{
			Name:  t.Name(),
			Level: hclog.Trace,
		})

		// ******************
		// ** Controller 1 **
		// ******************
		conf1, err := config.DevController()
		require.NoError(err)

		pl1, err := net.Listen("tcp", "[::1]:0")
		require.NoError(err)
		c1 := controller.NewTestController(t, &controller.TestControllerOpts{
			Config:                 conf1,
			InitialResourcesSuffix: "1234567890",
			Logger:                 logger.Named("c1"),
			PublicClusterAddr:      pl1.Addr().String(),
			WorkerRPCGracePeriod:   controllerGracePeriod(burdenCase),
		})

		// ******************
		// ** Controller 2 **
		// ******************
		pl2, err := net.Listen("tcp", "[::1]:0")
		require.NoError(err)
		c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
			Logger:               logger.Named("c2"),
			PublicClusterAddr:    pl2.Addr().String(),
			WorkerRPCGracePeriod: controllerGracePeriod(burdenCase),
		})

		wg := new(sync.WaitGroup)
		wg.Add(2)
		go func() {
			defer wg.Done()
			helper.ExpectWorkers(t, c1)
		}()
		go func() {
			defer wg.Done()
			helper.ExpectWorkers(t, c2)
		}()
		wg.Wait()

		// *************
		// ** Proxy 1 **
		// *************
		require.Len(c1.ClusterAddrs(), 1)
		p1, err := dawdle.NewProxy("tcp", "", c1.ClusterAddrs()[0],
			dawdle.WithListener(pl1),
			dawdle.WithRbufSize(256),
			dawdle.WithWbufSize(256),
		)
		require.NoError(err)
		t.Cleanup(func() {
			_ = p1.Close()
		})
		require.NotEmpty(t, p1.ListenerAddr())

		// *************
		// ** Proxy 2 **
		// *************
		require.Len(c2.ClusterAddrs(), 1)
		p2, err := dawdle.NewProxy("tcp", "", c2.ClusterAddrs()[0],
			dawdle.WithListener(pl2),
			dawdle.WithRbufSize(256),
			dawdle.WithWbufSize(256),
		)
		require.NoError(err)
		t.Cleanup(func() {
			_ = p2.Close()
		})
		require.NotEmpty(t, p2.ListenerAddr())

		// ************
		// ** Worker **
		// ************
		w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
			WorkerAuthKms:    c1.Config().WorkerAuthKms,
			InitialUpstreams: []string{p1.ListenerAddr(), p2.ListenerAddr()},
			Logger:           logger.Named("w1"),
			SuccessfulControllerRPCGracePeriodDuration: helper.DefaultControllerRPCGracePeriod,
			WorkerRPCInterval:                          500 * time.Millisecond,
		})

		wg.Add(2)
		go func() {
			defer wg.Done()
			helper.ExpectWorkers(t, c1, w1)
		}()
		go func() {
			defer wg.Done()
			helper.ExpectWorkers(t, c2, w1)
		}()
		wg.Wait()

		// Use an independent context for test things that take a context so
		// that we aren't tied to any timeouts in the controller, etc. This
		// can interfere with some of the test operations.
		ctx := context.Background()

		// Connect target
		client := c1.Client()
		client.SetToken(c1.Token().Token)
		tcl := targets.NewClient(client)
		tgt, err := tcl.Read(ctx, "ttcp_1234567890")
		require.NoError(err)
		require.NotNil(tgt)

		// Create test server, update default port on target
		ts := helper.NewTestTcpServer(t)
		require.NotNil(ts)
		t.Cleanup(ts.Close)
		tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(-1))
		require.NoError(err)
		require.NotNil(tgt)

		// Authorize and connect
		sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890")
		sConn := sess.Connect(ctx, t)

		// Run initial send/receive test, make sure things are working
		t.Log("running initial send/recv test")
		sConn.TestSendRecvAll(t)

		// Wait for a session info to be sent to the server, so the controller has
		// at least one record of the connection.
		w1.Worker().TestWaitForNextSuccessfulSessionInfoUpdate(t)

		// Kill connection to first controller, and run test again, should
		// pass, deferring to other controller. Wait for the next
		// successful status report to ensure this.
		t.Log("pausing link to controller #1")
		p1.Pause()
		w1.Worker().TestWaitForNextSuccessfulSessionInfoUpdate(t)
		sConn.TestSendRecvAll(t)

		// Resume first controller, pause second. This one should work too.
		t.Log("pausing link to controller #2, resuming #1")
		p1.Resume()
		p2.Pause()
		w1.Worker().TestWaitForNextSuccessfulSessionInfoUpdate(t)

		// Kill the first controller connection again. This one should fail
		// due to lack of any connection.
		t.Log("pausing link to controller #1 again, both connections should be offline")
		p1.Pause()

		// Wait for failure connection state (depends on burden case)
		switch burdenCase {
		case timeoutBurdenTypeWorker:
			// Wait on worker, then check controller
			sess.ExpectConnectionStateOnWorker(ctx, t, w1, session.StatusClosed)
			sess.ExpectConnectionStateOnController(ctx, t, c1.Controller().ConnectionRepoFn, session.StatusConnected)

		default:
			// Should be closed on both worker and controller. Wait on
			// worker then check controller.
			sess.ExpectConnectionStateOnWorker(ctx, t, w1, session.StatusClosed)
			sess.ExpectConnectionStateOnController(ctx, t, c1.Controller().ConnectionRepoFn, session.StatusClosed)
		}

		// Run send/receive test again to check expected connection-level
		// behavior
		sConn.TestSendRecvFail(t)

		// Finally resume both, try again. Should behave as per normal.
		t.Log("resuming connections to both controllers")
		p1.Resume()
		p2.Resume()
		w1.Worker().TestWaitForNextSuccessfulSessionInfoUpdate(t)

		// Do something post-reconnect depending on burden case. Note in
		// the default case, both worker and controller should be
		// relatively in sync, so we don't worry about these
		// post-reconnection assertions.
		switch burdenCase {
		case timeoutBurdenTypeWorker:
			// If we are expecting the worker to be the source of truth of
			// a connection status, ensure that our old session's
			// connections are actually closed now that the worker is
			// properly reporting in again.
			sess.ExpectConnectionStateOnController(ctx, t, c1.Controller().ConnectionRepoFn, session.StatusClosed)
		}

		// Proceed with new connection test
		t.Log("connecting to new session after resuming controller/worker link")
		sess = helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890") // re-assign, other connection will close in t.Cleanup()
		sConn = sess.Connect(ctx, t)
		sConn.TestSendRecvAll(t)
	}
}
