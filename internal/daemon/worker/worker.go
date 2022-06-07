package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/nodeenrollment"
	"github.com/mr-tron/base58"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/worker/internal/metric"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/nodeenrollment/multihop"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
	nodeefile "github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	ua "go.uber.org/atomic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/protobuf/proto"
)

type randFn func(length int) (string, error)

type Worker struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	tickerWg sync.WaitGroup

	grpcClientConn *atomic.Value

	controllerStatusConn *atomic.Value
	everAuthenticated    *ua.Bool
	lastStatusSuccess    *atomic.Value
	workerStartTime      time.Time

	controllerResolver *atomic.Value

	controllerSessionConn *atomic.Value
	sessionInfoMap        *sync.Map

	controllerMultihopConn *atomic.Value

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
	WorkerAuthStorage             *nodeefile.Storage
	WorkerAuthCurrentKeyId        *ua.String
	WorkerAuthRegistrationRequest string
	workerAuthSplitListener       *nodeenet.SplitListener

	// Test-specific options (and possibly hidden dev-mode flags)
	TestOverrideX509VerifyDnsName  string
	TestOverrideX509VerifyCertPool *x509.CertPool
	TestOverrideAuthRotationPeriod time.Duration
}

func New(conf *Config) (*Worker, error) {
	metric.InitializeHttpCollectors(conf.PrometheusRegisterer)
	metric.InitializeWebsocketCollectors(conf.PrometheusRegisterer)
	metric.InitializeClusterClientCollectors(conf.PrometheusRegisterer)

	w := &Worker{
		conf:                   conf,
		logger:                 conf.Logger.Named("worker"),
		started:                ua.NewBool(false),
		grpcClientConn:         new(atomic.Value),
		controllerStatusConn:   new(atomic.Value),
		everAuthenticated:      ua.NewBool(false),
		lastStatusSuccess:      new(atomic.Value),
		controllerResolver:     new(atomic.Value),
		controllerSessionConn:  new(atomic.Value),
		sessionInfoMap:         new(sync.Map),
		controllerMultihopConn: new(atomic.Value),
		tags:                   new(atomic.Value),
		updateTags:             ua.NewBool(false),
		nonceFn:                base62.Random,
		WorkerAuthCurrentKeyId: new(ua.String),
	}

	w.lastStatusSuccess.Store((*LastStatusInformation)(nil))
	w.controllerResolver.Store((*manual.Resolver)(nil))

	if conf.RawConfig.Worker == nil {
		conf.RawConfig.Worker = new(config.Worker)
	}

	w.ParseAndStoreTags(conf.RawConfig.Worker.Tags)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Worker.Name, err = w.conf.RawConfig.Worker.InitNameIfEmpty(); err != nil {
		return nil, fmt.Errorf("error auto-generating worker name: %w", err)
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

	w.WorkerAuthStorage, err = nodeefile.New(w.baseContext,
		nodeefile.WithBaseDirectory(w.conf.RawConfig.Worker.AuthStoragePath))
	if err != nil {
		return nil, err
	}

	return w, nil
}

func (w *Worker) Start() error {
	const op = "worker.(Worker).Start"

	w.baseContext, w.baseCancel = context.WithCancel(context.Background())

	if w.started.Load() {
		event.WriteSysEvent(w.baseContext, op, "already started, skipping")
		return nil
	}

	scheme := strconv.FormatInt(time.Now().UnixNano(), 36)
	controllerResolver := manual.NewBuilderWithScheme(scheme)
	w.controllerResolver.Store(controllerResolver)

	if w.conf.WorkerAuthKms == nil {
		// In this section, we look for existing worker credentials. The two
		// variables below store whether to create new credentials and whether
		// to create a fetch request so it can be displayed in the worker
		// startup info. These may be different because if initial creds have
		// been generated on the worker side but not yet authorized/fetched from
		// the controller, we don't want to invalidate that request on restart
		// by generating a new set of credentials. However it's safe to output a
		// new fetch request so we do in fact do that.
		var createNodeAuthCreds bool
		var createFetchRequest bool
		nodeCreds, err := types.LoadNodeCredentials(w.baseContext, w.WorkerAuthStorage, nodeenrollment.CurrentId, nodeenrollment.WithWrapper(w.conf.WorkerAuthStorageKms))
		switch {
		case err == nil:
			// It's unclear why this would ever happen -- it shouldn't -- so
			// this is simply safety against panics if something goes
			// catastrophically wrong
			if nodeCreds == nil {
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

		// NOTE: this block _must_ be before the `if createFetchRequest` block
		// or the fetch request may have no credentials to work with
		if createNodeAuthCreds {
			nodeCreds, err = types.NewNodeCredentials(
				w.baseContext,
				w.WorkerAuthStorage,
				nodeenrollment.WithRandomReader(w.conf.SecureRandomReader),
				nodeenrollment.WithWrapper(w.conf.WorkerAuthStorageKms),
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

	if err := w.startListeners(); err != nil {
		return fmt.Errorf("error starting worker listeners: %w", err)
	}
	if err := w.StartControllerConnections(); err != nil {
		return fmt.Errorf("error making controller connections: %w", err)
	}

	// Rather than deal with some of the potential error conditions for Add on
	// the waitgroup vs. Done (in case a function exits immediately), we will
	// always start rotation and simply exit early if we're using KMS, and
	// always add 2 here.
	w.tickerWg.Add(2)
	go func() {
		defer w.tickerWg.Done()
		w.startStatusTicking(w.baseContext)
	}()
	go func() {
		defer w.tickerWg.Done()
		w.startAuthRotationTicking(w.baseContext)
	}()

	w.workerStartTime = time.Now()
	w.started.Store(true)

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

	// Stop listeners first to prevent new connections to the
	// controller.
	defer w.started.Store(false)
	w.Resolver().UpdateState(resolver.State{Addresses: []resolver.Address{}})
	w.baseCancel()

	if err := w.stopServersAndListeners(); err != nil {
		return fmt.Errorf("error stopping worker servers and listeners: %w", err)
	}

	// Shut down all connections.
	w.cleanupConnections(w.baseContext, true)

	// Wait for next status request to succeed. Don't wait too long;
	// wrap the base context in a timeout equal to our status grace
	// period.
	waitStatusStart := time.Now()
	nextStatusCtx, nextStatusCancel := context.WithTimeout(w.baseContext, w.conf.StatusGracePeriodDuration)
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
	w.Resolver().UpdateState(resolver.State{Addresses: []resolver.Address{}})

	w.started.Store(false)
	w.tickerWg.Wait()
	if w.conf.Eventer != nil {
		if err := w.conf.Eventer.FlushNodes(context.Background()); err != nil {
			return fmt.Errorf("error flushing worker eventer nodes: %w", err)
		}
	}

	return nil
}

func (w *Worker) Resolver() *manual.Resolver {
	raw := w.controllerResolver.Load()
	if raw == nil {
		panic("nil resolver")
	}
	return raw.(*manual.Resolver)
}

func (w *Worker) ParseAndStoreTags(incoming map[string][]string) {
	if len(incoming) == 0 {
		w.tags.Store([]*servers.TagPair{})
		return
	}
	tags := []*servers.TagPair{}
	for k, vals := range incoming {
		for _, v := range vals {
			tags = append(tags, &servers.TagPair{
				Key:   k,
				Value: v,
			})
		}
	}
	w.tags.Store(tags)
	w.updateTags.Store(true)
}

// GrpcClientConn returns the underlying client connection
func (w *Worker) GrpcClientConn() (*grpc.ClientConn, error) {
	rawConn := w.grpcClientConn.Load()
	if rawConn == nil {
		return nil, errors.New("unable to load grpc client conn")
	}
	cc, ok := rawConn.(*grpc.ClientConn)
	if !ok {
		return nil, fmt.Errorf("invalid grpc client connection %T", rawConn)
	}
	if cc == nil {
		return nil, fmt.Errorf("client connection is nil")
	}

	return cc, nil
}

// ControllerSessionConn returns the underlying session service client
func (w *Worker) ControllerSessionConn() (pbs.SessionServiceClient, error) {
	rawConn := w.controllerSessionConn.Load()
	if rawConn == nil {
		return nil, errors.New("unable to load controller session service connection")
	}
	sessClient, ok := rawConn.(pbs.SessionServiceClient)
	if !ok {
		return nil, fmt.Errorf("invalid session client %T", rawConn)
	}
	if sessClient == nil {
		return nil, fmt.Errorf("session client is nil")
	}

	return sessClient, nil
}

// ControllerServerCoordinationServiceConn returns the underlying server coordination service client
func (w *Worker) ControllerServerCoordinationServiceConn() (pbs.ServerCoordinationServiceClient, error) {
	rawConn := w.controllerStatusConn.Load()
	if rawConn == nil {
		return nil, errors.New("unable to load controller service coordination service connection")
	}
	statusClient, ok := rawConn.(pbs.ServerCoordinationServiceClient)
	if !ok {
		return nil, fmt.Errorf("invalid service coordination service client %T", rawConn)
	}
	if statusClient == nil {
		return nil, fmt.Errorf("service coordination service client is nil")
	}

	return statusClient, nil
}

// ControllerMultihopConn returns the underlying multihop service client
func (w *Worker) ControllerMultihopConn() (multihop.MultihopServiceClient, error) {
	rawConn := w.controllerMultihopConn.Load()
	if rawConn == nil {
		return nil, errors.New("unable to load controller multihop service connection")
	}
	multihopClient, ok := rawConn.(multihop.MultihopServiceClient)
	if !ok {
		return nil, fmt.Errorf("invalid multihop client %T", rawConn)
	}
	if multihopClient == nil {
		return nil, fmt.Errorf("session multihop is nil")
	}

	return multihopClient, nil
}

func (w *Worker) getSessionTls(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	const op = "worker.(Worker).getSessionTls"
	ctx := w.baseContext
	var sessionId string
	switch {
	case strings.HasPrefix(hello.ServerName, globals.SessionPrefix):
		sessionId = hello.ServerName
	default:
		for _, proto := range hello.SupportedProtos {
			if strings.HasPrefix(proto, globals.SessionPrefix) {
				sessionId = proto
				break
			}
		}
	}

	if sessionId == "" {
		event.WriteSysEvent(ctx, op, "session_id not found in either SNI or ALPN protos", "server_name", hello.ServerName, "alpn_protos", hello.SupportedProtos)
		return nil, fmt.Errorf("could not find session ID in SNI or ALPN protos")
	}

	conn, err := w.ControllerSessionConn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfo("failed to create controller session client"))
	}

	timeoutContext, cancel := context.WithTimeout(w.baseContext, session.ValidateSessionTimeout)
	defer cancel()

	resp, err := conn.LookupSession(timeoutContext, &pbs.LookupSessionRequest{
		ServerId:    w.conf.RawConfig.Worker.Name,
		SessionId:   sessionId,
		WorkerKeyId: w.WorkerAuthCurrentKeyId.Load(),
	})
	if err != nil {
		return nil, fmt.Errorf("error validating session: %w", err)
	}

	if resp.GetExpiration().AsTime().Before(time.Now()) {
		return nil, fmt.Errorf("session is expired")
	}

	parsedCert, err := x509.ParseCertificate(resp.GetAuthorization().Certificate)
	if err != nil {
		return nil, fmt.Errorf("error parsing session certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{resp.GetAuthorization().Certificate},
				PrivateKey:  ed25519.PrivateKey(resp.GetAuthorization().PrivateKey),
				Leaf:        parsedCert,
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
			return errors.New("no peer certificates provided")
		}
		_, err := cs.PeerCertificates[0].Verify(verifyOpts)
		return err
	}

	si := &session.Info{
		Id:                    resp.GetAuthorization().GetSessionId(),
		SessionTls:            tlsConf,
		LookupSessionResponse: resp,
		Status:                resp.GetStatus(),
		ConnInfoMap:           make(map[string]*session.ConnInfo),
	}
	// TODO: Periodically clean this up. We can't rely on things in here but
	// not in cancellation because they could be on the way to being
	// established. However, since cert lifetimes are short, we can simply range
	// through and remove values that are expired.
	actualSiRaw, loaded := w.sessionInfoMap.LoadOrStore(sessionId, si)
	if loaded {
		// Update the response to the latest
		actualSi := actualSiRaw.(*session.Info)
		actualSi.Lock()
		actualSi.LookupSessionResponse = resp
		actualSi.Unlock()
	}

	return tlsConf, nil
}
