// Copyright (c) HashiCorp, Inc.
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
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
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
	var addrs []string
	lastStatus := tw.w.LastStatusSuccess()
	for _, v := range lastStatus.GetCalculatedUpstreams() {
		addrs = append(addrs, v.Address)
	}

	return addrs
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
	SuccessfulStatusGracePeriodDuration time.Duration

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
		configOpts = append(configOpts, config.TestWithErrorEventsEnabled(t, opts.EnableErrorEvents))
		opts.Config, err = config.DevWorker(configOpts...)
		if err != nil {
			t.Fatal(err)
		}
		if opts.Name != "" {
			opts.Config.Worker.Name = opts.Name
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

	if opts.SuccessfulStatusGracePeriodDuration != 0 {
		opts.Config.Worker.SuccessfulStatusGracePeriodDuration = opts.SuccessfulStatusGracePeriodDuration
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
		tw.Shutdown()
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
			tw.Shutdown()
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
		WorkerAuthKms:                       tw.w.conf.WorkerAuthKms,
		DownstreamWorkerAuthKms:             tw.w.conf.DownstreamWorkerAuthKms,
		WorkerAuthStorageKms:                tw.w.conf.WorkerAuthStorageKms,
		Name:                                opts.Name,
		InitialUpstreams:                    tw.UpstreamAddrs(),
		Logger:                              tw.w.conf.Logger,
		SuccessfulStatusGracePeriodDuration: opts.SuccessfulStatusGracePeriodDuration,
		WorkerAuthDebuggingEnabled:          tw.w.conf.WorkerAuthDebuggingEnabled,
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

// NewTestMultihopWorkers creates a PKI-KMS and PKI worker with the controller
// as an upstream, and two child workers (one PKI, one KMS) as downstreams of
// the initial workers (child PKI -> upstream PKI-KMS, child PKI-KMS -> upstream
// PKI). Tags for the PKI and child PKI/KMS workers can be passed in, if
// desired.
func NewTestMultihopWorkers(t testing.TB,
	logger hclog.Logger,
	controllerContext context.Context,
	clusterAddrs []string,
	workerAuthKms wrapping.Wrapper,
	serversRepoFn common.ServersRepoFactory,
	pkiTags, childPkiTags, childKmsTags map[string][]string,
	enableAuthDebugging *atomic.Bool,
) (kmsWorker, pkiWorker, childPkiWorker, childKmsWorker *TestWorker) {
	require := require.New(t)

	// Create a few test wrappers for the child KMS worker to use
	childDownstreamWrapper1 := db.TestWrapper(t)
	childDownstreamWrapper2 := db.TestWrapper(t)
	childDownstreamWrapper, err := multi.NewPooledWrapper(context.Background(), childDownstreamWrapper1)
	require.NoError(err)
	added, err := childDownstreamWrapper.AddWrapper(context.Background(), childDownstreamWrapper2)
	require.NoError(err)
	require.True(added)

	kmsWorker = NewTestWorker(t, &TestWorkerOpts{
		WorkerAuthKms:              workerAuthKms,
		InitialUpstreams:           clusterAddrs,
		Logger:                     logger.Named("kmsWorker"),
		WorkerAuthDebuggingEnabled: enableAuthDebugging,
		DownstreamWorkerAuthKms:    childDownstreamWrapper,
	})
	t.Cleanup(kmsWorker.Shutdown)

	// Give time for it to be inserted into the database
	time.Sleep(2 * time.Second)

	// names should not be set when using pki workers
	pkiWorkerConf, err := config.DevWorker()
	require.NoError(err)
	pkiWorkerConf.Worker.Name = ""
	if pkiTags != nil {
		pkiWorkerConf.Worker.Tags = pkiTags
	}
	pkiWorkerConf.Worker.InitialUpstreams = clusterAddrs
	pkiWorker = NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams:           clusterAddrs,
		Logger:                     logger.Named("pkiWorker"),
		Config:                     pkiWorkerConf,
		DownstreamWorkerAuthKms:    childDownstreamWrapper,
		WorkerAuthDebuggingEnabled: enableAuthDebugging,
	})
	t.Cleanup(pkiWorker.Shutdown)

	// Give time for it to be inserted into the database
	time.Sleep(2 * time.Second)

	// Get a server repo and worker auth repo
	serversRepo, err := serversRepoFn()
	require.NoError(err)
	// Perform initial authentication of worker to controller
	reqBytes, err := base58.FastBase58Decoding(pkiWorker.Worker().WorkerAuthRegistrationRequest)
	require.NoError(err)

	// Decode the proto into the request and create the worker
	pkiWorkerReq := new(types.FetchNodeCredentialsRequest)
	require.NoError(proto.Unmarshal(reqBytes, pkiWorkerReq))
	_, err = serversRepo.CreateWorker(controllerContext, &server.Worker{
		Worker: &store.Worker{
			ScopeId: scope.Global.String(),
		},
	}, server.WithFetchNodeCredentialsRequest(pkiWorkerReq))
	require.NoError(err)

	childPkiWorkerConf, err := config.DevWorker()
	require.NoError(err)
	childPkiWorkerConf.Worker.Name = ""
	if childPkiTags != nil {
		childPkiWorkerConf.Worker.Tags = childPkiTags
	}
	childPkiWorkerConf.Worker.InitialUpstreams = kmsWorker.ProxyAddrs()

	childPkiWorker = NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams:           kmsWorker.ProxyAddrs(),
		Logger:                     logger.Named("childPkiWorker"),
		Config:                     childPkiWorkerConf,
		WorkerRecordingStoragePath: t.TempDir(),
		WorkerAuthDebuggingEnabled: enableAuthDebugging,
	})
	t.Cleanup(childPkiWorker.Shutdown)

	// Give time for it to be inserted into the database
	time.Sleep(2 * time.Second)

	// Perform initial authentication of worker to controller
	reqBytes, err = base58.FastBase58Decoding(childPkiWorker.Worker().WorkerAuthRegistrationRequest)
	require.NoError(err)

	// Decode the proto into the request and create the worker
	childPkiWorkerReq := new(types.FetchNodeCredentialsRequest)
	require.NoError(proto.Unmarshal(reqBytes, childPkiWorkerReq))
	_, err = serversRepo.CreateWorker(controllerContext, &server.Worker{
		Worker: &store.Worker{
			ScopeId: scope.Global.String(),
		},
	}, server.WithFetchNodeCredentialsRequest(childPkiWorkerReq))
	require.NoError(err)

	childKmsWorkerConf, err := config.DevWorker()
	require.NoError(err)
	childKmsWorkerConf.Worker.Name = "child-kms-worker"
	childKmsWorkerConf.Worker.Description = "child-kms-worker description"
	// Set tags the same
	if childKmsTags != nil {
		childKmsWorkerConf.Worker.Tags = childKmsTags
	}
	childKmsWorkerConf.Worker.InitialUpstreams = kmsWorker.ProxyAddrs()

	childKmsWorker = NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams:           pkiWorker.ProxyAddrs(),
		Logger:                     logger.Named("childKmsWorker"),
		Config:                     childKmsWorkerConf,
		WorkerAuthKms:              childDownstreamWrapper2,
		WorkerAuthDebuggingEnabled: enableAuthDebugging,
		DisableAutoStart:           true,
	})
	childKmsWorker.w.conf.WorkerAuthStorageKms = nil

	err = childKmsWorker.w.Start()
	t.Cleanup(childKmsWorker.Shutdown)
	if err != nil {
		t.Fatal(err)
	}

	// Sleep so that workers can startup and connect.
	time.Sleep(12 * time.Second)

	return kmsWorker, pkiWorker, childPkiWorker, childKmsWorker
}

// NewAuthorizedPkiTestWorker creates a new test worker with the provided upstreams
// and creates it in the provided repo as an authorized worker. It returns
// The TestWorker and it's boundary id.
func NewAuthorizedPkiTestWorker(t *testing.T, repo *server.Repository, name string, upstreams []string) (*TestWorker, string) {
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
