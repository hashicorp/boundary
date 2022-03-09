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

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	ua "go.uber.org/atomic"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
)

type Worker struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	tickerWg sync.WaitGroup

	controllerStatusConn *atomic.Value
	lastStatusSuccess    *atomic.Value
	workerStartTime      time.Time

	controllerResolver *atomic.Value

	controllerSessionConn *atomic.Value
	sessionInfoMap        *sync.Map

	listeners []*base.ServerListener

	// We store the current set in an atomic value so that we can add
	// reload-on-sighup behavior later
	tags *atomic.Value
	// This stores whether or not to send updated tags on the next status
	// request. It can be set via startup in New below, or (eventually) via
	// SIGHUP.
	updateTags ua.Bool

	// Test-related values
	testReuseAuthNonces bool
	testReusedAuthNonce string
}

func New(conf *Config) (*Worker, error) {
	w := &Worker{
		conf:                  conf,
		logger:                conf.Logger.Named("worker"),
		started:               ua.NewBool(false),
		controllerStatusConn:  new(atomic.Value),
		lastStatusSuccess:     new(atomic.Value),
		controllerResolver:    new(atomic.Value),
		controllerSessionConn: new(atomic.Value),
		sessionInfoMap:        new(sync.Map),
		tags:                  new(atomic.Value),
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
			w.listeners = append(w.listeners, l)
		}
	}
	if len(w.listeners) == 0 {
		return nil, fmt.Errorf("no proxy listeners found")
	}

	return w, nil
}

func (w *Worker) Start() error {
	const op = "worker.(Worker).Start"
	if w.started.Load() {
		event.WriteSysEvent(w.baseContext, op, "already started, skipping")
		return nil
	}

	w.baseContext, w.baseCancel = context.WithCancel(context.Background())

	scheme := strconv.FormatInt(time.Now().UnixNano(), 36)
	controllerResolver := manual.NewBuilderWithScheme(scheme)
	w.controllerResolver.Store(controllerResolver)

	if err := w.startListeners(); err != nil {
		return fmt.Errorf("error starting worker listeners: %w", err)
	}
	if err := w.startControllerConnections(); err != nil {
		return fmt.Errorf("error making controller connections: %w", err)
	}

	w.tickerWg.Add(1)
	go func() {
		defer w.tickerWg.Done()
		w.startStatusTicking(w.baseContext)
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
		w.tags.Store(map[string]*servers.TagValues{})
		return
	}
	tags := make(map[string]*servers.TagValues, len(incoming))
	for k, v := range incoming {
		tags[k] = &servers.TagValues{
			Values: append(make([]string, 0, len(v)), v...),
		}
	}
	w.tags.Store(tags)
	w.updateTags.Store(true)
}

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

func (w *Worker) getSessionTls(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	const op = "worker.(Worker).getSessionTls"
	ctx := w.baseContext
	var sessionId string
	switch {
	case strings.HasPrefix(hello.ServerName, "s_"):
		sessionId = hello.ServerName
	default:
		event.WriteSysEvent(ctx, op, "invalid session in SNI", "session_id", hello.ServerName)
		return nil, fmt.Errorf("could not find session ID in SNI")
	}

	conn, err := w.ControllerSessionConn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfo("failed to create controller session client"))
	}

	timeoutContext, cancel := context.WithTimeout(w.baseContext, session.ValidateSessionTimeout)
	defer cancel()

	resp, err := conn.LookupSession(timeoutContext, &pbs.LookupSessionRequest{
		ServerId:  w.conf.RawConfig.Worker.Name,
		SessionId: sessionId,
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

	if len(parsedCert.DNSNames) != 1 {
		return nil, fmt.Errorf("invalid length of DNS names (%d) in parsed certificate", len(parsedCert.DNSNames))
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
		ServerName: parsedCert.DNSNames[0],
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  certPool,
		MinVersion: tls.VersionTLS13,
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
