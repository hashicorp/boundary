// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/cluster"
	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/internal/metric"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pb "github.com/hashicorp/boundary/internal/gen/controller/servers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	wpbs "github.com/hashicorp/boundary/internal/gen/worker/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/storage"
	boundary_plugin_assets "github.com/hashicorp/boundary/plugins/boundary"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	external_plugins "github.com/hashicorp/boundary/sdk/plugins"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/hashicorp/nodeenrollment"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
	nodeefile "github.com/hashicorp/nodeenrollment/storage/file"
	nodeeinmem "github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/prometheus/client_golang/prometheus"
	ua "go.uber.org/atomic"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/protobuf/proto"
)

type randFn func(length int) (string, error)

// reverseConnReceiver defines a min interface which must be met by a
// Worker.downstreamReceiver field
type reverseConnReceiver interface {
	// StartConnectionMgmtTicking starts a ticker which manages the receiver's
	// connections.
	StartConnectionMgmtTicking(context.Context, func() string, int) error

	// StartProcessingPendingConnections is a function that continually
	// processes incoming connections. This only returns when the provided context
	// is done.
	StartProcessingPendingConnections(context.Context, func() string) error
}

// graphContainer is a struct that exists purely so we can perform
// atomic swap operations on the interface, to avoid/fix data races in tests
// (and any other potential location).
// This is used to interact with downstream workers DAG
type graphContainer struct {
	graph
}

// graph provides at least a minimum interface that must be met by a
// Worker.downstreamWorkers field which is far better than allowing any (empty
// interface)
type graph interface {
	// RootId returns the root ID of the graph
	RootId() string
}

// recorderManager updates the session info updates with relevant recording
// information
type recorderManager interface {
	// ReauthorizeAllExcept should be called with the result of the session info update
	// to reauthorize all recorders for the relevant sessions except the ones provided
	ReauthorizeAllExcept(ctx context.Context, closedSessions []string) error
	// SessionsManaged gets the list of session ids managed by this recorderManager
	SessionsManaged(ctx context.Context) ([]string, error)
	// Shutdown must be called prior to exiting the process
	Shutdown(ctx context.Context)
}

// reverseConnReceiverFactory provides a simple factory which a Worker can use to
// create its reverseConnReceiver
var reverseConnReceiverFactory func(*atomic.Int64) (reverseConnReceiver, error)

var recordingStorageFactory func(
	ctx context.Context,
	path string,
	plgClients map[string]plgpb.StoragePluginServiceClient,
	enableLoopback bool,
	minimumAvailableDiskSpace uint64,
) (storage.RecordingStorage, error)

var recorderManagerFactory func(*Worker) (recorderManager, error)

var eventListenerFactory func(*Worker) (event.EventListener, error)

var initializeReverseGrpcClientCollectors = noopInitializePromCollectors

func noopInitializePromCollectors(r prometheus.Registerer) {}

var hostServiceServerFactory func(
	ctx context.Context,
	plgClients map[string]plgpb.HostPluginServiceClient,
	enableLoopback bool,
) (wpbs.HostServiceServer, error)

const (
	authenticationStatusNeverAuthenticated uint32 = iota
	authenticationStatusFirstAuthentication
	authenticationStatusFirstRoutingInfoRpcSuccessful
)

type Worker struct {
	conf *Config
	// receives address updates and contains the grpc resolver.
	addressReceivers []addressReceiver
	// confAddressReceiversLock is used to protect the conf field
	// and the addressReceivers field.
	confAddressReceiversLock sync.Mutex

	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	tickerWg sync.WaitGroup

	// grpc.ClientConns are thread safe. See
	// https://github.com/grpc/grpc-go/blob/master/Documentation/concurrency.md#clients
	// However this is an atomic because we sometimes swap this pointer out
	// (mostly in tests) - which isn't thread safe. This is exported for tests.
	GrpcClientConn atomic.Pointer[grpc.ClientConn]

	sessionManager session.Manager

	recorderManager recorderManager

	everAuthenticated      *ua.Uint32
	lastSessionInfoSuccess *atomic.Value
	lastRoutingInfoSuccess *atomic.Value
	lastStatisticsSuccess  *atomic.Value
	workerStartTime        time.Time
	operationalState       *atomic.Value
	// localStorageState is the current state of the local storage.
	// The local storage state is updated based on the local storage events.
	localStorageState *atomic.Value

	storageEventListener    event.EventListener
	upstreamConnectionState *atomic.Value

	controllerMultihopConn *atomic.Value

	controllerUpstreamMsgConn atomic.Pointer[handlers.UpstreamMessageServiceClientProducer]

	proxyListener *base.ServerListener

	// Used to generate a random nonce for Controller connections
	nonceFn randFn

	tags *atomic.Value
	// This stores whether or not to send updated tags on the next routing info
	// request. It can be set via startup in New below, or via
	// SIGHUP.
	updateTags *ua.Bool

	// The storage for node enrollment
	WorkerAuthStorage             nodeenrollment.Storage
	WorkerAuthCurrentKeyId        *ua.String
	WorkerAuthRegistrationRequest string
	workerAuthSplitListener       *nodeenet.SplitListener

	// The storage for session recording
	RecordingStorage storage.RecordingStorage

	// downstream workers and routes to those workers
	downstreamWorkers  *atomic.Pointer[graphContainer]
	downstreamReceiver reverseConnReceiver

	// Timing variables. These are atomics for SIGHUP support, and are int64
	// because they are casted to time.Duration.
	successfulRoutingInfoGracePeriod *atomic.Int64
	successfulSessionInfoGracePeriod *atomic.Int64
	// Note: Statistics does not require a grace period,
	// because we do not perform any special action based
	// on whether it is successful or not, unlike for SessionInfo
	// and RoutingInfo.

	statisticsCallTimeoutDuration       *atomic.Int64
	sessionInfoCallTimeoutDuration      *atomic.Int64
	routingInfoCallTimeoutDuration      *atomic.Int64
	getDownstreamWorkersTimeoutDuration *atomic.Int64

	// The time intervals at which the worker will invoke the controller RPCs.
	// Defaults to common.SessionInfoInterval, common.RoutingInfoInterval
	// and common.StatisticsInterval and is only overridden by the
	// TestWorkerRPCInterval test config.
	sessionInfoInterval time.Duration
	routingInfoInterval time.Duration
	statisticsInterval  time.Duration

	// AuthRotationNextRotation is useful in tests to understand how long to
	// sleep
	AuthRotationNextRotation atomic.Pointer[time.Time]

	// Test-specific options (and possibly hidden dev-mode flags)
	TestOverrideX509VerifyDnsName  string
	TestOverrideX509VerifyCertPool *x509.CertPool
	TestOverrideAuthRotationPeriod time.Duration

	downstreamConnManager *cluster.DownstreamManager

	HostServiceServer wpbs.HostServiceServer

	// SshKnownHostsCallback is used to provide a ssh.HostKeyCallback for SSH host key verification
	// when connecting to an SSH target. This is an atomic because it can be updated at runtime via SIGHUP.
	SshKnownHostsCallback atomic.Pointer[ssh.HostKeyCallback]
}

func New(ctx context.Context, conf *Config) (*Worker, error) {
	const op = "worker.New"
	metric.InitializeHttpCollectors(conf.PrometheusRegisterer)
	metric.InitializeWebsocketCollectors(conf.PrometheusRegisterer)
	metric.InitializeClusterClientCollectors(conf.PrometheusRegisterer)
	initializeReverseGrpcClientCollectors(conf.PrometheusRegisterer)

	baseContext, baseCancel := context.WithCancel(context.Background())
	w := &Worker{
		baseContext:            baseContext,
		baseCancel:             baseCancel,
		conf:                   conf,
		logger:                 conf.Logger.Named("worker"),
		started:                ua.NewBool(false),
		everAuthenticated:      ua.NewUint32(authenticationStatusNeverAuthenticated),
		lastSessionInfoSuccess: new(atomic.Value),
		lastRoutingInfoSuccess: new(atomic.Value),
		lastStatisticsSuccess:  new(atomic.Value),
		controllerMultihopConn: new(atomic.Value),
		// controllerUpstreamMsgConn:   new(atomic.Value),
		tags:                                new(atomic.Value),
		updateTags:                          ua.NewBool(false),
		nonceFn:                             base62.Random,
		WorkerAuthCurrentKeyId:              new(ua.String),
		operationalState:                    new(atomic.Value),
		downstreamConnManager:               cluster.NewDownstreamManager(),
		localStorageState:                   new(atomic.Value),
		successfulRoutingInfoGracePeriod:    new(atomic.Int64),
		successfulSessionInfoGracePeriod:    new(atomic.Int64),
		statisticsCallTimeoutDuration:       new(atomic.Int64),
		sessionInfoCallTimeoutDuration:      new(atomic.Int64),
		routingInfoCallTimeoutDuration:      new(atomic.Int64),
		getDownstreamWorkersTimeoutDuration: new(atomic.Int64),
		upstreamConnectionState:             new(atomic.Value),
		downstreamWorkers:                   new(atomic.Pointer[graphContainer]),
	}

	w.operationalState.Store(server.UnknownOperationalState)
	w.localStorageState.Store(server.UnknownLocalStorageState)
	w.lastSessionInfoSuccess.Store((*lastSessionInfo)(nil))
	w.lastRoutingInfoSuccess.Store((*LastRoutingInfo)(nil))
	w.lastStatisticsSuccess.Store((*lastStatistics)(nil))
	scheme := strconv.FormatInt(time.Now().UnixNano(), 36)
	controllerResolver := manual.NewBuilderWithScheme(scheme)
	w.addressReceivers = []addressReceiver{&grpcResolverReceiver{controllerResolver}}

	if conf.RawConfig.Worker == nil {
		conf.RawConfig.Worker = new(config.Worker)
	}

	if w.conf.RawConfig.Worker.RecordingStoragePath == "" {
		w.localStorageState.Store(server.NotConfiguredLocalStorageState)
	}

	if w.conf.RawConfig.Worker.SshKnownHostsPath != "" {
		cb, err := knownhosts.New(w.conf.RawConfig.Worker.SshKnownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("error loading ssh known hosts file: %w", err)
		}
		w.SshKnownHostsCallback.Store(&cb)
	}

	pluginLogger, err := event.NewHclogLogger(ctx, w.conf.Server.Eventer)
	if err != nil {
		return nil, fmt.Errorf("error creating plugin logger: %w", err)
	}

	w.HostServiceServer = wpbs.UnimplementedHostServiceServer{}
	if hostServiceServerFactory != nil {
		enableLoopback := false

		hostPlgClients := make(map[string]plgpb.HostPluginServiceClient)
		for _, enabledPlugin := range w.conf.Server.EnabledPlugins {
			switch {
			case enabledPlugin == base.EnabledPluginHostAzure && !w.conf.SkipPlugins,
				enabledPlugin == base.EnabledPluginGCP && !w.conf.SkipPlugins,
				enabledPlugin == base.EnabledPluginAws && !w.conf.SkipPlugins:
				pluginType := strings.ToLower(enabledPlugin.String())
				client, cleanup, err := external_plugins.CreateHostPlugin(
					ctx,
					pluginType,
					external_plugins.WithPluginOptions(
						pluginutil.WithPluginExecutionDirectory(conf.RawConfig.Plugins.ExecutionDir),
						pluginutil.WithPluginsFilesystem(boundary_plugin_assets.PluginPrefix, boundary_plugin_assets.FileSystem()),
					),
					external_plugins.WithLogger(pluginLogger.Named(pluginType)),
				)
				if err != nil {
					return nil, fmt.Errorf("error creating %s host plugin: %w", pluginType, err)
				}
				conf.ShutdownFuncs = append(conf.ShutdownFuncs, cleanup)
				hostPlgClients[pluginType] = client
			case enabledPlugin == base.EnabledPluginLoopback:
				enableLoopback = true
			}
		}
		hs, err := hostServiceServerFactory(ctx, hostPlgClients, enableLoopback)
		if err != nil {
			return nil, fmt.Errorf("failed to create host service server: %w", err)
		}
		w.HostServiceServer = hs
	}

	if w.conf.RawConfig.Worker.RecordingStoragePath != "" && recordingStorageFactory != nil {
		plgClients := make(map[string]plgpb.StoragePluginServiceClient)
		var enableStorageLoopback bool

		for _, enabledPlugin := range w.conf.Server.EnabledPlugins {
			switch {
			case enabledPlugin == base.EnabledPluginMinio && !w.conf.SkipPlugins:
				fallthrough
			case enabledPlugin == base.EnabledPluginAws && !w.conf.SkipPlugins:
				pluginType := strings.ToLower(enabledPlugin.String())
				client, cleanup, err := external_plugins.CreateStoragePlugin(
					ctx,
					pluginType,
					external_plugins.WithPluginOptions(
						pluginutil.WithPluginExecutionDirectory(conf.RawConfig.Plugins.ExecutionDir),
						pluginutil.WithPluginsFilesystem(boundary_plugin_assets.PluginPrefix, boundary_plugin_assets.FileSystem()),
					),
					external_plugins.WithLogger(pluginLogger.Named(pluginType)),
				)
				if err != nil {
					return nil, fmt.Errorf("error creating %s storage plugin: %w", pluginType, err)
				}
				conf.ShutdownFuncs = append(conf.ShutdownFuncs, cleanup)
				plgClients[pluginType] = client
			case enabledPlugin == base.EnabledPluginLoopback:
				enableStorageLoopback = true
			}
		}

		// passing in an empty context so that storage can finish syncing during an emergency shutdown or interrupt
		s, err := recordingStorageFactory(
			context.Background(),
			w.conf.RawConfig.Worker.RecordingStoragePath,
			plgClients, enableStorageLoopback,
			w.conf.RawConfig.Worker.RecordingStorageMinimumAvailableDiskSpace,
		)
		if err != nil {
			return nil, fmt.Errorf("error create recording storage: %w", err)
		}
		w.RecordingStorage = s
	}

	w.parseAndStoreTags(conf.RawConfig.Worker.Tags)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	if !conf.RawConfig.DisableMlock {
		// Ensure our memory usage is locked into physical RAM
		if err := mlock.LockMemory(); err != nil {
			return nil, fmt.Errorf(
				"Failed to lock memory: %v\n\n"+
					"This usually means that the mlock syscall is not available.\n"+
					"Boundary uses mlock to prevent memory from being swapped to\n"+
					"disk. This requires root privileges as well as a machine\n"+
					"that supports mlock. Please enable mlock on your system or\n"+
					"disable Boundary from using it. To disable Boundary from using it,\n"+
					"set the `disable_mlock` configuration option in your configuration\n"+
					"file.",
				err)
		}
	}
	switch conf.RawConfig.Worker.SuccessfulControllerRPCGracePeriodDuration {
	case 0:
		w.successfulRoutingInfoGracePeriod.Store(int64(server.DefaultLiveness))
		w.successfulSessionInfoGracePeriod.Store(int64(server.DefaultLiveness))
	default:
		w.successfulRoutingInfoGracePeriod.Store(int64(conf.RawConfig.Worker.SuccessfulControllerRPCGracePeriodDuration))
		w.successfulSessionInfoGracePeriod.Store(int64(conf.RawConfig.Worker.SuccessfulControllerRPCGracePeriodDuration))
	}
	switch conf.RawConfig.Worker.ControllerRPCCallTimeoutDuration {
	case 0:
		w.routingInfoCallTimeoutDuration.Store(int64(common.DefaultRoutingInfoTimeout))
		w.statisticsCallTimeoutDuration.Store(int64(common.DefaultStatisticsTimeout))
		w.sessionInfoCallTimeoutDuration.Store(int64(common.DefaultSessionInfoTimeout))
	default:
		w.routingInfoCallTimeoutDuration.Store(int64(conf.RawConfig.Worker.ControllerRPCCallTimeoutDuration))
		w.statisticsCallTimeoutDuration.Store(int64(conf.RawConfig.Worker.ControllerRPCCallTimeoutDuration))
		w.sessionInfoCallTimeoutDuration.Store(int64(conf.RawConfig.Worker.ControllerRPCCallTimeoutDuration))
	}
	switch conf.RawConfig.Worker.GetDownstreamWorkersTimeoutDuration {
	case 0:
		w.getDownstreamWorkersTimeoutDuration.Store(int64(server.DefaultLiveness))
	default:
		w.getDownstreamWorkersTimeoutDuration.Store(int64(conf.RawConfig.Worker.GetDownstreamWorkersTimeoutDuration))
	}
	// FIXME: This is really ugly, but works.
	session.CloseCallTimeout.Store(w.successfulSessionInfoGracePeriod.Load())

	w.sessionInfoInterval = common.SessionInfoInterval
	w.routingInfoInterval = common.RoutingInfoInterval
	w.statisticsInterval = common.StatisticsInterval
	// Override the routing info interval if it is set in the config.
	// This should only be used by tests.
	if conf.RawConfig.Worker.TestWorkerRPCInterval > 0 {
		w.sessionInfoInterval = conf.RawConfig.Worker.TestWorkerRPCInterval
		w.routingInfoInterval = conf.RawConfig.Worker.TestWorkerRPCInterval
		w.statisticsInterval = conf.RawConfig.Worker.TestWorkerRPCInterval
	}

	if reverseConnReceiverFactory != nil {
		var err error
		w.downstreamReceiver, err = reverseConnReceiverFactory(w.getDownstreamWorkersTimeoutDuration)
		if err != nil {
			return nil, fmt.Errorf("%s: error creating reverse connection receiver: %w", op, err)
		}
	}

	if eventListenerFactory != nil {
		var err error
		w.storageEventListener, err = eventListenerFactory(w)
		if err != nil {
			return nil, fmt.Errorf("error calling eventListenerFactory: %w", err)
		}
	}

	if recorderManagerFactory != nil {
		var err error
		w.recorderManager, err = recorderManagerFactory(w)
		if err != nil {
			return nil, fmt.Errorf("error calling recorderManagerFactory: %w", err)
		}
	}

	var listenerCount int
	for i := range conf.Listeners {
		l := conf.Listeners[i]
		if l == nil || l.Config == nil || l.Config.Purpose == nil {
			continue
		}
		if len(l.Config.Purpose) != 1 {
			return nil, fmt.Errorf("found listener with multiple purposes %q", strings.Join(l.Config.Purpose, ","))
		}
		switch l.Config.Purpose[0] {
		case "proxy":
			if w.proxyListener == nil {
				w.proxyListener = l
			}
			listenerCount++
		}
	}
	if listenerCount != 1 {
		return nil, fmt.Errorf("exactly one proxy listener is required")
	}

	return w, nil
}

// Reload will update a worker with a new Config. The worker will only use
// relevant parts of the new config, specifically:
// - Worker Tags
// - Initial Upstream addresses
func (w *Worker) Reload(ctx context.Context, newConf *config.Config) {
	const op = "worker.(Worker).Reload"

	w.parseAndStoreTags(newConf.Worker.Tags)

	switch newConf.Worker.SuccessfulControllerRPCGracePeriodDuration {
	case 0:
		w.successfulRoutingInfoGracePeriod.Store(int64(server.DefaultLiveness))
		w.successfulSessionInfoGracePeriod.Store(int64(server.DefaultLiveness))
	default:
		w.successfulRoutingInfoGracePeriod.Store(int64(newConf.Worker.SuccessfulControllerRPCGracePeriodDuration))
		w.successfulSessionInfoGracePeriod.Store(int64(newConf.Worker.SuccessfulControllerRPCGracePeriodDuration))
	}
	switch newConf.Worker.ControllerRPCCallTimeoutDuration {
	case 0:
		w.routingInfoCallTimeoutDuration.Store(int64(common.DefaultRoutingInfoTimeout))
		w.statisticsCallTimeoutDuration.Store(int64(common.DefaultStatisticsTimeout))
		w.sessionInfoCallTimeoutDuration.Store(int64(common.DefaultSessionInfoTimeout))
	default:
		w.routingInfoCallTimeoutDuration.Store(int64(newConf.Worker.ControllerRPCCallTimeoutDuration))
		w.statisticsCallTimeoutDuration.Store(int64(newConf.Worker.ControllerRPCCallTimeoutDuration))
		w.sessionInfoCallTimeoutDuration.Store(int64(newConf.Worker.ControllerRPCCallTimeoutDuration))
	}
	switch newConf.Worker.GetDownstreamWorkersTimeoutDuration {
	case 0:
		w.getDownstreamWorkersTimeoutDuration.Store(int64(server.DefaultLiveness))
	default:
		w.getDownstreamWorkersTimeoutDuration.Store(int64(newConf.Worker.GetDownstreamWorkersTimeoutDuration))
	}

	switch newConf.Worker.SshKnownHostsPath {
	case "":
		w.SshKnownHostsCallback.Store(nil)
	default:
		cb, err := knownhosts.New(newConf.Worker.SshKnownHostsPath)
		if err != nil {
			event.WriteError(w.baseContext, op, fmt.Errorf("error loading ssh known hosts file: %w", err))
			break
		}
		w.SshKnownHostsCallback.Store(&cb)
	}

	// See comment about this in worker.go
	session.CloseCallTimeout.Store(w.successfulRoutingInfoGracePeriod.Load())

	w.confAddressReceiversLock.Lock()
	defer w.confAddressReceiversLock.Unlock()
	if !slices.Equal(newConf.Worker.InitialUpstreams, w.conf.RawConfig.Worker.InitialUpstreams) {
		upstreamsMessage := fmt.Sprintf(
			"Initial Upstreams has changed; old upstreams were: %s, new upstreams are: %s",
			w.conf.RawConfig.Worker.InitialUpstreams,
			newConf.Worker.InitialUpstreams,
		)
		event.WriteSysEvent(ctx, op, upstreamsMessage)
		w.conf.RawConfig.Worker.InitialUpstreams = newConf.Worker.InitialUpstreams

		for _, ar := range w.addressReceivers {
			ar.SetAddresses(w.conf.RawConfig.Worker.InitialUpstreams)
			// set InitialAddresses in case the worker has not successfully dialed yet
			ar.InitialAddresses(w.conf.RawConfig.Worker.InitialUpstreams)
		}
	}
}

func (w *Worker) Start() error {
	const op = "worker.(Worker).Start"
	if w.started.Load() {
		event.WriteSysEvent(w.baseContext, op, "already started, skipping")
		return nil
	}

	// In this section, we look for existing worker credentials. The two
	// variables below store whether to create new credentials and whether to
	// create a fetch request so it can be displayed in the worker startup info.
	// These may be different because if initial creds have been generated on
	// the worker side but not yet authorized/fetched from the controller, we
	// don't want to invalidate that request on restart by generating a new set
	// of credentials. However it's safe to output a new fetch request so we do
	// in fact do that.
	//
	// Note that if a controller-generated activation token has been supplied,
	// we do not output a fetch request; we attempt to use that directly later.
	//
	// If we have a stable storage path we use that; if no path is supplied
	// (e.g. when using KMS) we use inmem storage.
	var err error
	if w.conf.RawConfig.Worker.AuthStoragePath != "" {
		w.WorkerAuthStorage, err = nodeefile.New(w.baseContext,
			nodeefile.WithBaseDirectory(w.conf.RawConfig.Worker.AuthStoragePath))
		if err != nil {
			return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error loading worker auth storage directory"))
		}
	} else {
		w.WorkerAuthStorage, err = nodeeinmem.New(w.baseContext)
		if err != nil {
			return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error loading in-mem worker auth storage"))
		}
	}

	var createNodeAuthCreds bool
	var createFetchRequest bool
	nodeCreds, err := types.LoadNodeCredentials(
		w.baseContext,
		w.WorkerAuthStorage,
		nodeenrollment.CurrentId,
		nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms))
	switch {
	case err == nil:
		if nodeCreds == nil {
			// It's unclear why this would ever happen -- it shouldn't -- so
			// this is simply safety against panics if something goes
			// catastrophically wrong
			event.WriteSysEvent(w.baseContext, op, "no error loading worker auth creds but nil creds, creating new creds for registration")
			createNodeAuthCreds = true
			createFetchRequest = true
			break
		}

		// Check that we have valid creds, or that we have generated creds but
		// simply are still waiting on authentication (in which case we don't
		// want to invalidate what we've already sent)
		var validCreds bool
		switch len(nodeCreds.CertificateBundles) {
		case 0:
			// Still waiting on initial creds, so don't invalidate the request
			// by creating new credentials. However, we will generate and
			// display a new valid request in case the first was lost.
			createFetchRequest = true

		default:
			now := time.Now()
			for _, bundle := range nodeCreds.CertificateBundles {
				if bundle.CertificateNotBefore.AsTime().Before(now) && bundle.CertificateNotAfter.AsTime().After(now) {
					// If we have a certificate in its validity period,
					// everything is fine
					validCreds = true
					break
				}
			}

			// Certificates are both expired, so create new credentials and
			// output a request based on those
			createNodeAuthCreds = !validCreds
			createFetchRequest = !validCreds
		}

	case errors.Is(err, nodeenrollment.ErrNotFound):
		// Nothing was found on disk, so create
		createNodeAuthCreds = true
		createFetchRequest = true

	default:
		// Some other type of error happened, bail out
		return fmt.Errorf("error loading worker auth creds: %w", err)
	}

	// Don't output a fetch request if an activation token has been
	// provided. Technically we _could_ still output a fetch request, and it
	// would be valid to do so, but if a token was provided it may well be
	// confusing to a user if it seems like it was ignored because a fetch
	// request was still output.
	if actToken := w.conf.RawConfig.Worker.ControllerGeneratedActivationToken; actToken != "" {
		createFetchRequest = false
	}

	// NOTE: this block _must_ be before the `if createFetchRequest` block
	// or the fetch request may have no credentials to work with
	if createNodeAuthCreds {
		nodeCreds, err = types.NewNodeCredentials(
			w.baseContext,
			w.WorkerAuthStorage,
			nodeenrollment.WithRandomReader(w.conf.SecureRandomReader),
			nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms),
		)
		if err != nil {
			return fmt.Errorf("error generating new worker auth creds: %w", err)
		}
	}

	if createFetchRequest {
		if nodeCreds == nil {
			return fmt.Errorf("need to create fetch request but worker auth creds are nil: %w", err)
		}
		req, err := nodeCreds.CreateFetchNodeCredentialsRequest(w.baseContext, nodeenrollment.WithRandomReader(w.conf.SecureRandomReader))
		if err != nil {
			return fmt.Errorf("error creating worker auth fetch credentials request: %w", err)
		}
		reqBytes, err := proto.Marshal(req)
		if err != nil {
			return fmt.Errorf("error marshaling worker auth fetch credentials request: %w", err)
		}
		w.WorkerAuthRegistrationRequest = base58.FastBase58Encoding(reqBytes)
		currentKeyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
		if err != nil {
			return fmt.Errorf("error deriving worker auth key id: %w", err)
		}
		w.WorkerAuthCurrentKeyId.Store(currentKeyId)
	}
	// Regardless, we want to load the currentKeyId
	currentKeyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	if err != nil {
		return fmt.Errorf("error deriving worker auth key id: %w", err)
	}
	w.WorkerAuthCurrentKeyId.Store(currentKeyId)

	if err := w.StartControllerConnections(); err != nil {
		return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error making controller connections"))
	}

	w.sessionManager, err = session.NewManager(pbs.NewSessionServiceClient(w.GrpcClientConn.Load()))
	if err != nil {
		return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error creating session manager"))
	}

	if err := w.startListeners(w.sessionManager); err != nil {
		return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error starting worker listeners"))
	}

	if w.storageEventListener != nil {
		if err := w.storageEventListener.Start(w.baseContext); err != nil {
			return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error starting worker event listener"))
		}

		if w.RecordingStorage != nil {
			w.localStorageState.Store(w.RecordingStorage.GetLocalStorageState(w.baseContext))
		}
	}

	w.operationalState.Store(server.ActiveOperationalState)

	// Rather than deal with some of the potential error conditions for Add on
	// the waitgroup vs. Done (in case a function exits immediately), we will
	// always start rotation and simply exit early if we're using KMS
	w.tickerWg.Add(2)
	go func() {
		defer w.tickerWg.Done()
		w.startRoutingInfoTicking(w.baseContext)
	}()
	go func() {
		defer w.tickerWg.Done()
		w.startAuthRotationTicking(w.baseContext)
	}()

	if w.downstreamReceiver != nil {
		w.tickerWg.Add(2)
		servNameFn := func() string {
			if s := w.LastRoutingInfoSuccess(); s != nil {
				return s.WorkerId
			}
			return "unknown worker id"
		}
		go func() {
			defer w.tickerWg.Done()
			if err := w.downstreamReceiver.StartProcessingPendingConnections(w.baseContext, servNameFn); err != nil {
				errors.Wrap(w.baseContext, err, op)
			}
		}()
		go func() {
			defer w.tickerWg.Done()
			err := w.downstreamReceiver.StartConnectionMgmtTicking(
				w.baseContext,
				servNameFn,
				-1, // indicates the ticker should run until cancelled.
			)
			if err != nil {
				errors.Wrap(w.baseContext, err, op)
			}
		}()
	}

	w.workerStartTime = time.Now()
	w.started.Store(true)

	return nil
}

// GracefulShutdownm sets the worker state to "shutdown" and will wait to return until there
// are no longer any active connections.
func (w *Worker) GracefulShutdown() error {
	const op = "worker.(Worker).GracefulShutdown"
	event.WriteSysEvent(w.baseContext, op, "worker entering graceful shutdown")
	w.operationalState.Store(server.ShutdownOperationalState)

	// As long as some routing info has been sent in the past, wait for 1 routing info
	// update to be sent since we've updated our operational state.
	lastRoutingInfoTime := w.lastSuccessfulRoutingInfoTime()
	if !lastRoutingInfoTime.Equal(w.workerStartTime) {
	WaitForRoutingInfo:
		for !lastRoutingInfoTime.Before(w.lastSuccessfulRoutingInfoTime()) {
			select {
			case <-w.baseContext.Done():
				event.WriteSysEvent(w.baseContext, op, "context done waiting for routing info to be sent")
				break WaitForRoutingInfo
			case <-time.After(time.Millisecond * 250):
			}
		}
	}

	// Wait for running proxy connections to drain
WaitForConnectionDrain:
	for proxy.ProxyState.CurrentProxiedConnections() > 0 {
		select {
		case <-w.baseContext.Done():
			event.WriteSysEvent(w.baseContext, op, "context done waiting for connections to be drained")
			break WaitForConnectionDrain
		case <-time.After(time.Millisecond * 250):
		}
	}
	event.WriteSysEvent(w.baseContext, op, "worker connections have drained")

	return nil
}

// Shutdown shuts down the workers. skipListeners can be used to not stop
// listeners, useful for tests if we want to stop and start a worker. In order
// to create new listeners we'd have to migrate listener setup logic here --
// doable, but work for later.
func (w *Worker) Shutdown() error {
	const op = "worker.(Worker).Shutdown"
	if !w.started.Load() {
		event.WriteSysEvent(w.baseContext, op, "already shut down, skipping")
		return nil
	}
	event.WriteSysEvent(w.baseContext, op, "worker shutting down")

	// Set state to shutdown
	w.operationalState.Store(server.ShutdownOperationalState)

	// Stop listeners first to prevent new connections to the
	// controller.
	defer w.started.Store(false)
	if err := w.stopServersAndListeners(); err != nil {
		return fmt.Errorf("error stopping worker servers and listeners: %w", err)
	}

	var recManWg sync.WaitGroup
	if w.recorderManager != nil {
		recManWg.Add(1)
		go func() {
			// Shutdown recorder manager to close all recorders, done in a go routine
			// since it will not force shutdown of channels until the passed in context
			// is Done.
			defer recManWg.Done()
			w.recorderManager.Shutdown(w.baseContext)
		}()
	}

	// Shut down all connections.
	w.cleanupConnections(w.baseContext, true, w.sessionManager)

	// Wait for next routing info request to succeed. Don't wait too long; time it out
	// at our default liveness value.
	nextRoutingInfoCtx, nextRoutingInfoCancel := context.WithTimeout(w.baseContext, server.DefaultLiveness)
	defer nextRoutingInfoCancel()
	lastRoutingInfoTime := w.lastSuccessfulRoutingInfoTime()
	if !lastRoutingInfoTime.Equal(w.workerStartTime) {
	WaitForRoutingInfo:
		for !lastRoutingInfoTime.Before(w.lastSuccessfulRoutingInfoTime()) {
			select {
			case <-nextRoutingInfoCtx.Done():
				event.WriteError(w.baseContext, op, nextRoutingInfoCtx.Err(), event.WithInfoMsg("error waiting for next routing info report to controller"))
				break WaitForRoutingInfo
			case <-time.After(time.Millisecond * 250):
			}
		}
	}

	// Proceed with remainder of shutdown.
	w.baseCancel()
	// Lock to protect w.addressReceivers
	w.confAddressReceiversLock.Lock()
	for _, ar := range w.addressReceivers {
		ar.SetAddresses(nil)
	}
	w.confAddressReceiversLock.Unlock()

	if w.storageEventListener != nil {
		err := w.storageEventListener.Shutdown(w.baseContext)
		if err != nil {
			return fmt.Errorf("error shutting down worker event listener: %w", err)
		}
	}

	w.started.Store(false)
	w.tickerWg.Wait()
	recManWg.Wait()

	if w.conf.Eventer != nil {
		if err := w.conf.Eventer.FlushNodes(context.Background()); err != nil {
			return fmt.Errorf("error flushing worker eventer nodes: %w", err)
		}
	}

	event.WriteSysEvent(w.baseContext, op, "worker finished shutting down")
	return nil
}

func (w *Worker) parseAndStoreTags(incoming map[string][]string) {
	if len(incoming) == 0 {
		w.tags.Store([]*pb.TagPair{})
		return
	}
	tags := []*pb.TagPair{}
	for k, vals := range incoming {
		for _, v := range vals {
			tags = append(tags, &pb.TagPair{
				Key:   k,
				Value: v,
			})
		}
	}
	w.tags.Store(tags)
	w.updateTags.Store(true)
}

func (w *Worker) getSessionTls(sessionManager session.Manager) func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	const op = "worker.(Worker).getSessionTls"
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		ctx := w.baseContext
		var sessionId string
		switch {
		case strings.HasPrefix(hello.ServerName, fmt.Sprintf("%s_", globals.SessionPrefix)):
			sessionId = hello.ServerName
		default:
			for _, proto := range hello.SupportedProtos {
				if strings.HasPrefix(proto, fmt.Sprintf("%s_", globals.SessionPrefix)) {
					sessionId = proto
					break
				}
			}
		}

		if sessionId == "" {
			event.WriteSysEvent(ctx, op, "session_id not found in either SNI or ALPN protos", "server_name", hello.ServerName)
			return nil, fmt.Errorf("could not find session ID in SNI or ALPN protos")
		}

		lastSuccess := w.LastRoutingInfoSuccess()
		if lastSuccess == nil {
			event.WriteSysEvent(ctx, op, "no last routing information found at session acceptance time")
			return nil, fmt.Errorf("no last routing information found at session acceptance time")
		}

		timeoutContext, cancel := context.WithTimeout(w.baseContext, session.ValidateSessionTimeout)
		defer cancel()
		sess, err := sessionManager.LoadLocalSession(timeoutContext, sessionId, lastSuccess.GetWorkerId())
		if err != nil {
			return nil, fmt.Errorf("error refreshing session: %w", err)
		}

		if sess.GetCertificate() == nil {
			return nil, fmt.Errorf("requested session has no certifificate")
		}
		if len(sess.GetCertificate().Raw) == 0 {
			return nil, fmt.Errorf("requested session has no certificate DER")
		}
		if len(sess.GetPrivateKey()) == 0 {
			return nil, fmt.Errorf("requested session has no private key")
		}

		certPool := x509.NewCertPool()
		certPool.AddCert(sess.GetCertificate())

		tlsConf := &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{sess.GetCertificate().Raw},
					PrivateKey:  ed25519.PrivateKey(sess.GetPrivateKey()),
					Leaf:        sess.GetCertificate(),
				},
			},
			NextProtos: []string{"http/1.1"},
			MinVersion: tls.VersionTLS13,

			// These two are set this way so we can make use of VerifyConnection,
			// which we set on this TLS config below. We are not skipping
			// verification!
			ClientAuth:         tls.RequireAnyClientCert,
			InsecureSkipVerify: true,
		}

		// We disable normal DNS SAN behavior as we don't rely on DNS or IP
		// addresses for security and want to avoid issues with including localhost
		// etc.
		verifyOpts := x509.VerifyOptions{
			DNSName: sessionId,
			Roots:   certPool,
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
		}
		if w.TestOverrideX509VerifyCertPool != nil {
			verifyOpts.Roots = w.TestOverrideX509VerifyCertPool
		}
		if w.TestOverrideX509VerifyDnsName != "" {
			verifyOpts.DNSName = w.TestOverrideX509VerifyDnsName
		}
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			// Go will not run this without at least one peer certificate, but
			// doesn't hurt to check
			if len(cs.PeerCertificates) == 0 {
				return errors.New(ctx, errors.InvalidParameter, op, "no peer certificates provided")
			}
			if subtle.ConstantTimeCompare(cs.PeerCertificates[0].Raw, sess.GetCertificate().Raw) != 1 {
				return errors.New(ctx, errors.InvalidParameter, op, "expected peer certificate to match session certificate")
			}
			_, err := cs.PeerCertificates[0].Verify(verifyOpts)
			return err
		}
		return tlsConf, nil
	}
}

// SendUpstreamMessage facilitates sending upstream messages to the controller.
func (w *Worker) SendUpstreamMessage(ctx context.Context, m proto.Message) (proto.Message, error) {
	const op = "worker.(Worker).SendUpstreamMessage"
	nodeCreds, err := types.LoadNodeCredentials(w.baseContext, w.WorkerAuthStorage, nodeenrollment.CurrentId, nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	initKeyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	clientProducer := w.controllerUpstreamMsgConn.Load()
	return handlers.SendUpstreamMessage(ctx, *clientProducer, initKeyId, m, handlers.WithKeyProducer(nodeCreds))
}
