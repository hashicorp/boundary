package worker

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// NewTestMultihopWorkers creates a KMS and PKI worker with the controller as an upstream, and a
// child PKI worker as a downstream of the KMS worker connected to the controller.
// Tags for the PKI and child PKI worker can be passed in, if desired
func NewTestMultihopWorkers(t testing.TB, logger hclog.Logger, controllerContext context.Context, clusterAddrs []string,
	workerAuthKms wrapping.Wrapper, serversRepoFn common.ServersRepoFactory, pkiTags,
	childPkiTags map[string][]string,
) (kmsWorker *TestWorker, pkiWorker *TestWorker, childPkiWorker *TestWorker) {
	require := require.New(t)
	kmsWorker = NewTestWorker(t, &TestWorkerOpts{
		WorkerAuthKms:    workerAuthKms,
		InitialUpstreams: clusterAddrs,
		Logger:           logger.Named("kmsWorker"),
	})

	// names should not be set when using pki workers
	pkiWorkerConf, err := config.DevWorker()
	require.NoError(err)
	pkiWorkerConf.Worker.Name = ""
	if pkiTags != nil {
		pkiWorkerConf.Worker.Tags = pkiTags
	}
	pkiWorkerConf.Worker.InitialUpstreams = clusterAddrs
	pkiWorker = NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams: clusterAddrs,
		Logger:           logger.Named("pkiWorker"),
		Config:           pkiWorkerConf,
	})
	t.Cleanup(pkiWorker.Shutdown)

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
		InitialUpstreams: kmsWorker.ProxyAddrs(),
		Logger:           logger.Named("childPkiWorker"),
		Config:           childPkiWorkerConf,
	})

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

	// Sleep so that DAG gets updated
	time.Sleep(10 * time.Second)

	return kmsWorker, pkiWorker, childPkiWorker
}

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

	// The worker credential storage KMS to use, or one will be created
	WorkerAuthStorageKms wrapping.Wrapper

	// The location of the worker's auth storage
	WorkerAuthStoragePath string

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
	StatusGracePeriodDuration time.Duration

	// Overrides worker's nonceFn, for cases where we want to have control
	// over the nonce we send to the Controller
	NonceFn randFn

	// If set, override the normal auth rotation period
	AuthRotationPeriod time.Duration
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

	if opts == nil {
		opts = new(TestWorkerOpts)
	}

	// Base server
	tw.b = base.NewServer(nil)
	tw.b.Command = &base.Command{
		Context:    ctx,
		ShutdownCh: make(chan struct{}),
	}

	// Get dev config, or use a provided one
	var err error
	if opts.Config == nil {
		opts.Config, err = config.DevWorker()
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

	// Initialize status grace period
	tw.b.SetStatusGracePeriodDuration(opts.StatusGracePeriodDuration)

	if opts.Config.Worker == nil {
		opts.Config.Worker = &config.Worker{
			Name: opts.Name,
		}
	}
	if opts.WorkerAuthStoragePath != "" {
		opts.Config.Worker.AuthStoragePath = opts.WorkerAuthStoragePath
		tw.b.DevUsePkiForUpstream = true
	}
	tw.name = opts.Config.Worker.Name

	serverName, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	serverName = fmt.Sprintf("%s/worker", serverName)
	if err := tw.b.SetupEventing(tw.b.Logger, tw.b.StderrLock, serverName, base.WithEventerConfig(opts.Config.Eventing)); err != nil {
		t.Fatal(err)
	}

	// Set up KMSes
	switch {
	case opts.WorkerAuthKms != nil:
		tw.b.WorkerAuthKms = opts.WorkerAuthKms
	case opts.WorkerAuthStorageKms != nil:
		tw.b.WorkerAuthStorageKms = opts.WorkerAuthStorageKms
	default:
		if err := tw.b.SetupKMSes(tw.b.Context, nil, opts.Config); err != nil {
			t.Fatal(err)
		}
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

	tw.w, err = New(conf)
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
		WorkerAuthKms:             tw.w.conf.WorkerAuthKms,
		WorkerAuthStorageKms:      tw.w.conf.WorkerAuthStorageKms,
		Name:                      opts.Name,
		InitialUpstreams:          tw.UpstreamAddrs(),
		Logger:                    tw.w.conf.Logger,
		StatusGracePeriodDuration: opts.StatusGracePeriodDuration,
	}
	if nextOpts.Name == "" {
		var err error
		nextOpts.Name, err = db.NewPublicId("w")
		if err != nil {
			t.Fatal(err)
		}
		nextOpts.Name = strings.ToLower(nextOpts.Name)
		event.WriteSysEvent(context.TODO(), op, "worker name generated", "name", nextOpts.Name)
	}
	return NewTestWorker(t, nextOpts)
}

// NewTestMultihopWorkers creates a KMS and PKI worker with the controller as an upstream, and a
// child PKI worker as a downstream of the PKI worker connected to the controller.
// Tags for the PKI and child PKI worker can be passed in, if desired
func NewTestMultihopWorkers(t testing.TB, logger hclog.Logger, controllerContext context.Context, clusterAddrs []string,
	workerAuthKms wrapping.Wrapper, serversRepoFn common.ServersRepoFactory, pkiTags,
	childPkiTags map[string][]string,
) (kmsWorker *TestWorker, pkiWorker *TestWorker, childPkiWorker *TestWorker) {
	require := require.New(t)
	kmsWorker = NewTestWorker(t, &TestWorkerOpts{
		WorkerAuthKms:    workerAuthKms,
		InitialUpstreams: clusterAddrs,
		Logger:           logger.Named("kmsWorker"),
	})

	// names should not be set when using pki workers
	pkiWorkerConf, err := config.DevWorker()
	require.NoError(err)
	pkiWorkerConf.Worker.Name = ""
	if pkiTags != nil {
		pkiWorkerConf.Worker.Tags = pkiTags
	}
	pkiWorkerConf.Worker.InitialUpstreams = clusterAddrs
	pkiWorker = NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams: clusterAddrs,
		Logger:           logger.Named("pkiWorker"),
		Config:           pkiWorkerConf,
	})
	t.Cleanup(pkiWorker.Shutdown)

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
		InitialUpstreams: kmsWorker.ProxyAddrs(),
		Logger:           logger.Named("childPkiWorker"),
		Config:           childPkiWorkerConf,
	})

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

	// Sleep so that workers can startup and connect.
	time.Sleep(10 * time.Second)

	return kmsWorker, pkiWorker, childPkiWorker
}
