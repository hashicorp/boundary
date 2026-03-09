// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// TestWorker wraps a base.Server and Worker to provide a
// fully-programmatic worker for tests. Error checking (for instance, for
// valid config) is not stringent at the moment.
type TestWorker struct {
	b              *base.Server
	w              *Worker
	t              testing.TB
	addrs          []string // The address the worker proxies are listening on
	ctx            context.Context
	cancel         context.CancelFunc
	name           string
	shutdownDoneCh chan struct{}
	shutdownOnce   *sync.Once
}

// Worker returns the underlying worker
func (tw *TestWorker) Worker() *Worker {
	return tw.w
}

func (tw *TestWorker) Config() *Config {
	return tw.w.conf
}

func (tw *TestWorker) Context() context.Context {
	return tw.ctx
}

func (tw *TestWorker) Cancel() {
	tw.cancel()
}

func (tw *TestWorker) Name() string {
	return tw.name
}

func (tw *TestWorker) UpstreamAddrs() []string {
	lastRoutingInfo := tw.w.LastRoutingInfoSuccess()
	return lastRoutingInfo.GetCalculatedUpstreamAddresses()
}

func (tw *TestWorker) ProxyAddrs() []string {
	if tw.addrs != nil {
		return tw.addrs
	}

	for _, listener := range tw.b.Listeners {
		if listener.Config.Purpose[0] == "proxy" {
			tcpAddr, ok := listener.ProxyListener.Addr().(*net.TCPAddr)
			if !ok {
				tw.t.Fatal("could not parse address as a TCP addr")
			}
			addr := net.JoinHostPort(tcpAddr.IP.String(), fmt.Sprintf("%d", tcpAddr.Port))
			tw.addrs = append(tw.addrs, addr)
		}
	}

	return tw.addrs
}

// TestSessionInfo provides detail about a particular session from
// the worker's local session state. This detail is a point-in-time
// snapshot of what's in sessionInfoMap for a particular session, and
// may not contain all of the information that is contained within
// it, or the underlying ConnInfoMap. Only details that are really
// important to testing are passed along.
type TestSessionInfo struct {
	Id     string
	Status pbs.SESSIONSTATUS

	// Connections is indexed by connection ID, which is also included
	// within TestConnectionInfo for convenience.
	Connections map[string]TestConnectionInfo
}

// TestConnectionInfo provides detail about a particular connection
// as a part of TestSessionInfo. See that struct for details about
// the purpose of this data and how it's gathered.
type TestConnectionInfo struct {
	Id        string
	Status    pbs.CONNECTIONSTATUS
	CloseTime time.Time
}

// LookupSession returns session info from the worker's local session
// state.
//
// The return boolean will be true if the session was found, false if
// it wasn't.
//
// See TestSessionInfo for details on how to use this info.
func (tw *TestWorker) LookupSession(id string) (TestSessionInfo, bool) {
	var result TestSessionInfo
	sess := tw.w.sessionManager.Get(id)
	if sess == nil {
		return TestSessionInfo{}, false
	}

	conns := make(map[string]TestConnectionInfo)
	for _, conn := range sess.GetLocalConnections() {
		conns[conn.Id] = TestConnectionInfo{
			Id:        conn.Id,
			Status:    conn.Status,
			CloseTime: conn.CloseTime,
		}
	}

	result.Id = sess.GetId()
	result.Status = sess.GetStatus()
	result.Connections = conns

	return result, true
}

// Shutdown runs any cleanup functions; be sure to run this after your test is
// done
func (tw *TestWorker) Shutdown() {
	tw.shutdownOnce.Do(func() {
		if tw.b != nil {
			close(tw.b.ShutdownCh)
		}

		tw.cancel()

		if tw.w != nil {
			if err := tw.w.Shutdown(); err != nil {
				tw.t.Error(err)
			}
		}
		if tw.b != nil {
			if err := tw.b.RunShutdownFuncs(); err != nil {
				tw.t.Error(err)
			}
		}

		close(tw.shutdownDoneCh)
	})
}

type TestWorkerOpts struct {
	// Config; if not provided a dev one will be created
	Config *config.Config

	// Sets initial upstream addresses
	InitialUpstreams []string

	// If true, the worker will not be started
	DisableAutoStart bool

	// The worker auth KMS to use, or one will be created
	WorkerAuthKms wrapping.Wrapper

	// The downstream worker auth KMS to use, or one will be created
	DownstreamWorkerAuthKms *multi.PooledWrapper

	// The worker credential storage KMS to use, or one will be created
	WorkerAuthStorageKms wrapping.Wrapper

	// The location of the worker's auth storage
	WorkerAuthStoragePath string

	// The location of the worker's recording storage
	WorkerRecordingStoragePath string

	// The interval between each respective worker RPC invocation
	// This sets the interval for SessionInfo, RoutingInfo and Statistics.
	WorkerRPCInterval time.Duration

	// The name to use for the worker, otherwise one will be randomly
	// generated, unless provided in a non-nil Config
	Name string

	// The logger to use, or one will be created
	Logger hclog.Logger

	// The registerer to use for registering all the collectors.  Nil means
	// no metrics are registered.
	PrometheusRegisterer prometheus.Registerer

	// The amount of time to wait before marking connections as closed when a
	// connection cannot be made back to the controller
	SuccessfulControllerRPCGracePeriodDuration time.Duration

	// Overrides worker's nonceFn, for cases where we want to have control
	// over the nonce we send to the Controller
	NonceFn randFn

	// If set, override the normal auth rotation period
	AuthRotationPeriod time.Duration

	// Toggle worker auth debugging
	WorkerAuthDebuggingEnabled *atomic.Bool

	// Enable audit events
	EnableAuditEvents bool

	// Enable system events
	EnableSysEvents bool

	// Enable observation events
	EnableObservationEvents bool

	// Enable IPv6
	EnableIPv6 bool

	// Enable error events
	EnableErrorEvents bool
}

func NewTestWorker(t testing.TB, opts *TestWorkerOpts) *TestWorker {
	const op = "worker.NewTestWorker"
	ctx, cancel := context.WithCancel(context.Background())

	tw := &TestWorker{
		t:              t,
		ctx:            ctx,
		cancel:         cancel,
		shutdownDoneCh: make(chan struct{}),
		shutdownOnce:   new(sync.Once),
	}
	t.Cleanup(tw.Shutdown)

	if opts == nil {
		opts = new(TestWorkerOpts)
	}

	// Base server
	tw.b = base.NewServer(nil)
	tw.b.WorkerAuthDebuggingEnabled = opts.WorkerAuthDebuggingEnabled
	tw.b.Command = &base.Command{
		Context:    ctx,
		ShutdownCh: make(chan struct{}),
	}

	// Get dev config, or use a provided one
	var err error
	if opts.Config == nil {
		var configOpts []config.Option
		configOpts = append(configOpts, config.WithAuditEventsEnabled(opts.EnableAuditEvents))
		configOpts = append(configOpts, config.WithSysEventsEnabled(opts.EnableSysEvents))
		configOpts = append(configOpts, config.WithObservationsEnabled(opts.EnableObservationEvents))
		configOpts = append(configOpts, config.WithIPv6Enabled(opts.EnableIPv6))
		configOpts = append(configOpts, config.TestWithErrorEventsEnabled(t, opts.EnableErrorEvents))
		opts.Config, err = config.DevWorker(configOpts...)
		if err != nil {
			t.Fatal(err)
		}
		if opts.Name != "" {
			opts.Config.Worker.Name = opts.Name
		}
		if opts.WorkerRPCInterval > 0 {
			opts.Config.Worker.TestWorkerRPCInterval = opts.WorkerRPCInterval
		}
	}

	if len(opts.InitialUpstreams) > 0 {
		opts.Config.Worker.InitialUpstreams = opts.InitialUpstreams
	}

	// Start a logger
	tw.b.Logger = opts.Logger
	if tw.b.Logger == nil {
		tw.b.Logger = hclog.New(&hclog.LoggerOptions{
			Level: hclog.Trace,
		})
	}

	tw.b.PrometheusRegisterer = opts.PrometheusRegisterer

	if opts.Config.Worker == nil {
		opts.Config.Worker = &config.Worker{
			Name: opts.Name,
		}
	}
	if opts.WorkerAuthStoragePath != "" {
		opts.Config.Worker.AuthStoragePath = opts.WorkerAuthStoragePath
	}
	if opts.WorkerRecordingStoragePath != "" {
		opts.Config.Worker.RecordingStoragePath = opts.WorkerRecordingStoragePath
	}

	tw.b.EnabledPlugins = append(tw.b.EnabledPlugins, base.EnabledPluginLoopback)
	tw.name = opts.Config.Worker.Name

	if opts.SuccessfulControllerRPCGracePeriodDuration != 0 {
		opts.Config.Worker.SuccessfulControllerRPCGracePeriodDuration = opts.SuccessfulControllerRPCGracePeriodDuration
	}

	serverName, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	serverName = fmt.Sprintf("%s/worker", serverName)
	if err := tw.b.SetupEventing(tw.b.Context, tw.b.Logger, tw.b.StderrLock, serverName, base.WithEventerConfig(opts.Config.Eventing)); err != nil {
		t.Fatal(err)
	}

	// Set up KMSes
	if err := tw.b.SetupKMSes(tw.b.Context, nil, opts.Config); err != nil {
		t.Fatal(err)
	}
	if opts.WorkerAuthKms != nil {
		tw.b.WorkerAuthKms = opts.WorkerAuthKms
	}
	if opts.WorkerAuthStorageKms != nil {
		tw.b.WorkerAuthStorageKms = opts.WorkerAuthStorageKms
	}
	if opts.DownstreamWorkerAuthKms != nil {
		tw.b.DownstreamWorkerAuthKms = opts.DownstreamWorkerAuthKms
	}

	// Ensure the listeners use random port allocation
	for _, listener := range opts.Config.Listeners {
		listener.RandomPort = true
	}
	if err := tw.b.SetupListeners(nil, opts.Config.SharedConfig, []string{"proxy"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.b.SetupWorkerPublicAddress(opts.Config, ""); err != nil {
		t.Fatal(err)
	}

	conf := &Config{
		RawConfig: opts.Config,
		Server:    tw.b,
	}

	tw.w, err = New(ctx, conf)
	if err != nil {
		t.Fatal(err)
	}

	tw.w.TestOverrideAuthRotationPeriod = opts.AuthRotationPeriod

	if opts.NonceFn != nil {
		tw.w.nonceFn = opts.NonceFn
	}

	// The real server functions will listen for shutdown cues and act so mimic
	// that here, and ensure that channels get drained
	go func() {
		for {
			select {
			case <-tw.b.ShutdownCh:
				tw.Shutdown()
			case <-tw.b.ServerSideShutdownCh:
				tw.Shutdown()
			case <-tw.shutdownDoneCh:
				return
			}
		}
	}()

	if !opts.DisableAutoStart {
		if err := tw.w.Start(); err != nil {
			t.Fatal(err)
		}
	}

	return tw
}

func (tw *TestWorker) AddClusterWorkerMember(t testing.TB, opts *TestWorkerOpts) *TestWorker {
	const op = "worker.(TestWorker).AddClusterWorkerMember"
	if opts == nil {
		opts = new(TestWorkerOpts)
	}
	nextOpts := &TestWorkerOpts{
		WorkerAuthKms:           tw.w.conf.WorkerAuthKms,
		DownstreamWorkerAuthKms: tw.w.conf.DownstreamWorkerAuthKms,
		WorkerAuthStorageKms:    tw.w.conf.WorkerAuthStorageKms,
		Name:                    opts.Name,
		InitialUpstreams:        tw.UpstreamAddrs(),
		Logger:                  tw.w.conf.Logger,
		SuccessfulControllerRPCGracePeriodDuration: opts.SuccessfulControllerRPCGracePeriodDuration,
		WorkerAuthDebuggingEnabled:                 tw.w.conf.WorkerAuthDebuggingEnabled,
	}
	if nextOpts.Name == "" {
		var err error
		nextOpts.Name, err = db.NewPublicId(context.Background(), "w")
		if err != nil {
			t.Fatal(err)
		}
		nextOpts.Name = strings.ToLower(nextOpts.Name)
		event.WriteSysEvent(context.TODO(), op, "worker name generated", "name", nextOpts.Name)
	}
	return NewTestWorker(t, nextOpts)
}

// NewAuthorizedPkiTestWorker creates a new test worker with the provided upstreams
// and creates it in the provided repo as an authorized worker. It returns
// The TestWorker and it's boundary id.
func NewAuthorizedPkiTestWorker(t *testing.T, repo *server.Repository, name string, upstreams []string, opt ...config.Option) (*TestWorker, string) {
	t.Helper()
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})
	wcfg, err := config.DevWorker()
	require.NoError(t, err)
	wcfg.Worker.Name = ""
	wcfg.Worker.InitialUpstreams = upstreams
	w := NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams: upstreams,
		Logger:           logger.Named(name),
		Config:           wcfg,
	})
	t.Cleanup(w.Shutdown)

	// Perform initial authentication of worker to controller
	reqBytes, err := base58.FastBase58Decoding(w.Worker().WorkerAuthRegistrationRequest)
	require.NoError(t, err)

	// Decode the proto into the request and create the worker
	pkiWorkerReq := new(types.FetchNodeCredentialsRequest)
	require.NoError(t, proto.Unmarshal(reqBytes, pkiWorkerReq))
	wr, err := repo.CreateWorker(context.Background(), &server.Worker{
		Worker: &store.Worker{
			Name:    name,
			ScopeId: scope.Global.String(),
		},
	}, server.WithFetchNodeCredentialsRequest(pkiWorkerReq))
	require.NoError(t, err)
	return w, wr.GetPublicId()
}

// mockServerCoordinationService is meant to stand in for a controller when testing
// the methods defined by the server coordination service. It allows applying assertions and specifying
// the return value of grpc methods by overwriting service methods.
type mockServerCoordinationService struct {
	pbs.UnimplementedServerCoordinationServiceServer
	nextReqAssert         func(*pbs.StatusRequest) (*pbs.StatusResponse, error)
	nextStatisticAssert   func(*pbs.StatisticsRequest) (*pbs.StatisticsResponse, error)
	nextSessionInfoAssert func(*pbs.SessionInfoRequest) (*pbs.SessionInfoResponse, error)
}

func (m mockServerCoordinationService) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	if m.nextReqAssert != nil {
		return m.nextReqAssert(req)
	}
	return nil, status.Error(codes.Unavailable, "Status not implemented")
}

func (m mockServerCoordinationService) Statistics(ctx context.Context, req *pbs.StatisticsRequest) (*pbs.StatisticsResponse, error) {
	if m.nextStatisticAssert != nil {
		return m.nextStatisticAssert(req)
	}
	return nil, status.Error(codes.Unavailable, "Statistics not implemented")
}

func (m mockServerCoordinationService) SessionInfo(ctx context.Context, req *pbs.SessionInfoRequest) (*pbs.SessionInfoResponse, error) {
	if m.nextSessionInfoAssert != nil {
		return m.nextSessionInfoAssert(req)
	}
	return nil, status.Error(codes.Unavailable, "SessionInfo not implemented")
}

var _ pbs.ServerCoordinationServiceServer = (*mockServerCoordinationService)(nil)

// TestWaitForNextSuccessfulSessionInfoUpdate waits for the next successful session info. It's
// used by testing in place of a more opaque and possibly unnecessarily long sleep for
// things like initial controller check-in, etc.
//
// The timeout is aligned with the worker's session info grace period.
func (w *Worker) TestWaitForNextSuccessfulSessionInfoUpdate(t testing.TB) {
	t.Helper()
	const op = "worker.(Worker).WaitForNextSuccessfulSessionInfoUpdate"
	waitStart := time.Now()
	ctx, cancel := context.WithTimeout(w.baseContext, time.Duration(w.successfulSessionInfoGracePeriod.Load()))
	defer cancel()
	t.Log("waiting for next session info report to controller")
	for {
		select {
		case <-time.After(time.Second):
			// pass

		case <-ctx.Done():
			t.Error("error waiting for next session info report to controller")
			return
		}

		si := w.lastSessionInfoSuccess.Load().(*lastSessionInfo)
		if si != nil && si.LastSuccessfulRequestTime.After(waitStart) {
			break
		}
	}

	t.Log("next worker session info update sent successfully")
}

// TestWaitForNextSuccessfulStatisticsUpdate waits for the next successful statistics. It's
// used by testing in place of a more opaque and possibly unnecessarily long sleep for
// things like initial controller check-in, etc.
//
// The timeout is aligned with twice the worker's statistics timeout duration.
func (w *Worker) TestWaitForNextSuccessfulStatisticsUpdate(t testing.TB) {
	t.Helper()
	const op = "worker.(Worker).WaitForNextSuccessfulStatisticsUpdate"
	waitStart := time.Now()
	ctx, cancel := context.WithTimeout(w.baseContext, time.Duration(2*w.statisticsCallTimeoutDuration.Load()))
	defer cancel()
	t.Log("waiting for next statistics report to controller")
	for {
		select {
		case <-time.After(time.Second):
			// pass

		case <-ctx.Done():
			t.Error("error waiting for next statistics report to controller")
			return
		}

		si := w.lastStatisticsSuccess.Load().(*lastStatistics)
		if si != nil && si.LastSuccessfulRequestTime.After(waitStart) {
			break
		}
	}

	t.Log("next worker statistics update sent successfully")
}
