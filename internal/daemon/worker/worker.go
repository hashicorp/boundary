// Copyright (c) HashiCorp, Inc.
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
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/storage"
	boundary_plugin_assets "github.com/hashicorp/boundary/plugins/boundary"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	external_plugins "github.com/hashicorp/boundary/sdk/plugins"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/nodeenrollment"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
	nodeefile "github.com/hashicorp/nodeenrollment/storage/file"
	nodeeinmem "github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/prometheus/client_golang/prometheus"
	ua "go.uber.org/atomic"
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

// downstreamers provides at least a minimum interface that must be met by a
// Worker.downstreamWorkers field which is far better than allowing any (empty
// interface)
type downstreamers interface {
	// RootId returns the root ID of the downstreamers' graph
	RootId() string
}

// recorderManager updates the status updates with relevant recording
// information
type recorderManager interface {
	// ReauthorizeAllExcept should be called with the result of the status update
	// to reauthorize all recorders for the relevant sessions except the ones provided
	ReauthorizeAllExcept(ctx context.Context, closedSessions []string) error
	// SessionsManaged gets the list of session ids managed by this recorderManager
	SessionsManaged(ctx context.Context) ([]string, error)
	// Shutdown must be called prior to exiting the process
	Shutdown(ctx context.Context)
}

// reverseConnReceiverFactory provides a simple factory which a Worker can use to
// create its reverseConnReceiver
var reverseConnReceiverFactory func() reverseConnReceiver

var recordingStorageFactory func(ctx context.Context, path string, plgClients map[string]plgpb.StoragePluginServiceClient, enableLoopback bool) (storage.RecordingStorage, error)

var recorderManagerFactory func(*Worker) (recorderManager, error)

var initializeReverseGrpcClientCollectors = noopInitializePromCollectors

func noopInitializePromCollectors(r prometheus.Registerer) {}

const (
	authenticationStatusNeverAuthenticated uint32 = iota
	authenticationStatusFirstAuthentication
	authenticationStatusFirstStatusRpcSuccessful
)

type Worker struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	tickerWg sync.WaitGroup

	// grpc.ClientConns are thread safe.
	// See https://github.com/grpc/grpc-go/blob/master/Documentation/concurrency.md#clients
	// This is exported for tests.
	GrpcClientConn *grpc.ClientConn

	// receives address updates and contains the grpc resolver.
	addressReceivers []addressReceiver

	sessionManager session.Manager

	recorderManager recorderManager

	everAuthenticated       *ua.Uint32
	lastStatusSuccess       *atomic.Value
	workerStartTime         time.Time
	operationalState        *atomic.Value
	upstreamConnectionState *atomic.Value

	controllerMultihopConn *atomic.Value

	controllerUpstreamMsgConn atomic.Pointer[handlers.UpstreamMessageServiceClientProducer]

	proxyListener *base.ServerListener

	// Used to generate a random nonce for Controller connections
	nonceFn randFn

	// We store the current set in an atomic value so that we can add
	// reload-on-sighup behavior later
	tags *atomic.Value
	// This stores whether or not to send updated tags on the next status
	// request. It can be set via startup in New below, or (eventually) via
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
	downstreamWorkers  downstreamers
	downstreamReceiver reverseConnReceiver

	// Timing variables. These are atomics for SIGHUP support, and are int64
	// because they are casted to time.Duration.
	successfulStatusGracePeriod *atomic.Int64
	statusCallTimeoutDuration   *atomic.Int64

	// AuthRotationNextRotation is useful in tests to understand how long to
	// sleep
	AuthRotationNextRotation atomic.Pointer[time.Time]

	// Test-specific options (and possibly hidden dev-mode flags)
	TestOverrideX509VerifyDnsName  string
	TestOverrideX509VerifyCertPool *x509.CertPool
	TestOverrideAuthRotationPeriod time.Duration

	statusLock sync.Mutex

	pkiConnManager *cluster.DownstreamManager
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
		lastStatusSuccess:      new(atomic.Value),
		controllerMultihopConn: new(atomic.Value),
		// controllerUpstreamMsgConn:   new(atomic.Value),
		tags:                        new(atomic.Value),
		updateTags:                  ua.NewBool(false),
		nonceFn:                     base62.Random,
		WorkerAuthCurrentKeyId:      new(ua.String),
		operationalState:            new(atomic.Value),
		pkiConnManager:              cluster.NewDownstreamManager(),
		successfulStatusGracePeriod: new(atomic.Int64),
		statusCallTimeoutDuration:   new(atomic.Int64),
		upstreamConnectionState:     new(atomic.Value),
	}

	w.operationalState.Store(server.UnknownOperationalState)

	if reverseConnReceiverFactory != nil {
		w.downstreamReceiver = reverseConnReceiverFactory()
	}

	w.lastStatusSuccess.Store((*LastStatusInformation)(nil))
	scheme := strconv.FormatInt(time.Now().UnixNano(), 36)
	controllerResolver := manual.NewBuilderWithScheme(scheme)
	w.addressReceivers = []addressReceiver{&grpcResolverReceiver{controllerResolver}}

	if conf.RawConfig.Worker == nil {
		conf.RawConfig.Worker = new(config.Worker)
	}

	if w.conf.RawConfig.Worker.RecordingStoragePath != "" && recordingStorageFactory != nil {
		pluginLogger, err := event.NewHclogLogger(ctx, w.conf.Server.Eventer)
		if err != nil {
			return nil, fmt.Errorf("error creating storage catalog plugin logger: %w", err)
		}
		plgClients := make(map[string]plgpb.StoragePluginServiceClient)
		var enableStorageLoopback bool

		for _, enabledPlugin := range w.conf.Server.EnabledPlugins {
			switch enabledPlugin {
			case base.EnabledPluginAws:
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
			case base.EnabledPluginLoopback:
				enableStorageLoopback = true
			}
		}

		// passing in an empty context so that storage can finish syncing during an emergency shutdown or interrupt
		s, err := recordingStorageFactory(context.Background(), w.conf.RawConfig.Worker.RecordingStoragePath, plgClients, enableStorageLoopback)
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
	switch conf.RawConfig.Worker.SuccessfulStatusGracePeriodDuration {
	case 0:
		w.successfulStatusGracePeriod.Store(int64(server.DefaultLiveness))
	default:
		w.successfulStatusGracePeriod.Store(int64(conf.RawConfig.Worker.SuccessfulStatusGracePeriodDuration))
	}
	switch conf.RawConfig.Worker.StatusCallTimeoutDuration {
	case 0:
		w.statusCallTimeoutDuration.Store(int64(common.DefaultStatusTimeout))
	default:
		w.statusCallTimeoutDuration.Store(int64(conf.RawConfig.Worker.StatusCallTimeoutDuration))
	}
	// FIXME: This is really ugly, but works.
	session.CloseCallTimeout = w.statusCallTimeoutDuration

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

	if !strutil.EquivalentSlices(newConf.Worker.InitialUpstreams, w.conf.RawConfig.Worker.InitialUpstreams) {
		w.statusLock.Lock()
		defer w.statusLock.Unlock()

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

	if !w.conf.RawConfig.Worker.UseDeprecatedKmsAuthMethod {
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
			if err != nil {
				return fmt.Errorf("error encoding worker auth registration request: %w", err)
			}
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
	}

	if err := w.StartControllerConnections(); err != nil {
		return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error making controller connections"))
	}

	var err error
	w.sessionManager, err = session.NewManager(pbs.NewSessionServiceClient(w.GrpcClientConn))
	if err != nil {
		return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error creating session manager"))
	}

	if err := w.startListeners(w.sessionManager); err != nil {
		return errors.Wrap(w.baseContext, err, op, errors.WithMsg("error starting worker listeners"))
	}

	w.operationalState.Store(server.ActiveOperationalState)

	// Rather than deal with some of the potential error conditions for Add on
	// the waitgroup vs. Done (in case a function exits immediately), we will
	// always start rotation and simply exit early if we're using KMS
	w.tickerWg.Add(2)
	go func() {
		defer w.tickerWg.Done()
		w.startStatusTicking(w.baseContext, w.sessionManager, &w.addressReceivers, w.recorderManager)
	}()
	go func() {
		defer w.tickerWg.Done()
		w.startAuthRotationTicking(w.baseContext)
	}()

	if w.downstreamReceiver != nil {
		w.tickerWg.Add(2)
		servNameFn := func() string {
			if s := w.LastStatusSuccess(); s != nil {
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

	// As long as some status has been sent in the past, wait for 2 status
	// updates to be sent since we've updated our operational state.
	lastStatusTime := w.lastSuccessfulStatusTime()
	if lastStatusTime != w.workerStartTime {
		for i := 0; i < 2; i++ {
			for {
				if lastStatusTime != w.lastSuccessfulStatusTime() {
					lastStatusTime = w.lastSuccessfulStatusTime()
					break
				}
				time.Sleep(time.Millisecond * 250)
			}
		}
	}

	// Wait for running proxy connections to drain
	for proxy.ProxyState.CurrentProxiedConnections() > 0 {
		time.Sleep(time.Millisecond * 250)
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

	// Wait for next status request to succeed. Don't wait too long; time it out
	// at our default liveness value, which is also our default status grace
	// period timeout
	waitStatusStart := time.Now()
	nextStatusCtx, nextStatusCancel := context.WithTimeout(w.baseContext, server.DefaultLiveness)
	defer nextStatusCancel()
	for {
		if err := nextStatusCtx.Err(); err != nil {
			event.WriteError(w.baseContext, op, err, event.WithInfoMsg("error waiting for next status report to controller"))
			break
		}

		if w.lastSuccessfulStatusTime().Sub(waitStatusStart) > 0 {
			break
		}

		time.Sleep(time.Second)
	}

	// Proceed with remainder of shutdown.
	w.baseCancel()
	for _, ar := range w.addressReceivers {
		ar.SetAddresses(nil)
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

		lastSuccess := w.LastStatusSuccess()
		if lastSuccess == nil {
			event.WriteSysEvent(ctx, op, "no last status information found at session acceptance time")
			return nil, fmt.Errorf("no last status information found at session acceptance time")
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
