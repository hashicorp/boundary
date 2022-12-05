package worker

import (
	"context"
	"crypto/tls"
	stderrers "errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cluster"
	"github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/daemon/worker/internal/metric"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-multierror"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
	"github.com/hashicorp/nodeenrollment/protocol"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/hashicorp/nodeenrollment/util/temperror"
	"google.golang.org/grpc"
)

// the function that handles a secondary connection over a provided listener
var handleSecondaryConnection = closeListener

func closeListener(_ context.Context, l net.Listener, _ any, _ int) error {
	if l != nil {
		return l.Close()
	}
	return nil
}

func (w *Worker) startListeners(sm session.Manager) error {
	const op = "worker.(Worker).startListeners"

	e := event.SysEventer()
	if e == nil {
		return fmt.Errorf("%s: sys eventer not initialized", op)
	}
	logger, err := e.StandardLogger(w.baseContext, "worker.listeners: ", event.ErrorType)
	if err != nil {
		return fmt.Errorf("%s: unable to initialize std logger: %w", op, err)
	}
	if w.proxyListener == nil {
		return fmt.Errorf("%s: nil proxy listener", op)
	}

	workerServer, err := w.configureForWorker(w.proxyListener, logger, sm)
	if err != nil {
		return fmt.Errorf("%s: failed to configure for worker: %w", op, err)
	}

	workerServer()

	return nil
}

func (w *Worker) configureForWorker(ln *base.ServerListener, logger *log.Logger, sessionManager session.Manager) (func(), error) {
	const op = "worker.configureForWorker"
	handler, err := w.handler(HandlerProperties{ListenerConfig: ln.Config}, sessionManager)
	if err != nil {
		return nil, err
	}

	cancelCtx := w.baseContext
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		ErrorLog:          logger,
		BaseContext: func(net.Listener) context.Context {
			return cancelCtx
		},
	}
	ln.HTTPServer = httpServer

	if ln.Config.HTTPReadHeaderTimeout > 0 {
		httpServer.ReadHeaderTimeout = ln.Config.HTTPReadHeaderTimeout
	}
	if ln.Config.HTTPReadTimeout > 0 {
		httpServer.ReadTimeout = ln.Config.HTTPReadTimeout
	}
	if ln.Config.HTTPWriteTimeout > 0 {
		httpServer.WriteTimeout = ln.Config.HTTPWriteTimeout
	}
	if ln.Config.HTTPIdleTimeout > 0 {
		httpServer.IdleTimeout = ln.Config.HTTPIdleTimeout
	}

	fetchCredsFn := func(
		ctx context.Context,
		_ nodee.Storage,
		req *types.FetchNodeCredentialsRequest,
		_ ...nodee.Option,
	) (*types.FetchNodeCredentialsResponse, error) {
		client := w.controllerMultihopConn.Load()
		if client == nil {
			return nil, temperror.New(stderrers.New("error fetching controller connection, client is nil"))
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, temperror.New(stderrers.New("client could not be understood as a multihop service client"))
		}
		return multihopClient.FetchNodeCredentials(ctx, req)
	}

	generateServerCertificatesFn := func(
		ctx context.Context,
		_ nodee.Storage,
		req *types.GenerateServerCertificatesRequest,
		_ ...nodee.Option,
	) (*types.GenerateServerCertificatesResponse, error) {
		client := w.controllerMultihopConn.Load()
		if client == nil {
			return nil, temperror.New(stderrers.New("error fetching controller connection, client is nil"))
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, temperror.New(stderrers.New("client could not be understood as a multihop service client"))
		}
		return multihopClient.GenerateServerCertificates(ctx, req)
	}

	interceptingListener, err := protocol.NewInterceptingListener(
		&protocol.InterceptingListenerConfiguration{
			Context:      w.baseContext,
			Storage:      w.WorkerAuthStorage,
			BaseListener: ln.ProxyListener,
			BaseTlsConfiguration: &tls.Config{
				GetConfigForClient: w.getSessionTls(sessionManager),
			},
			FetchCredsFunc:                 fetchCredsFn,
			GenerateServerCertificatesFunc: generateServerCertificatesFn,
		})
	if err != nil {
		return nil, fmt.Errorf("error instantiating node auth listener: %w", err)
	}

	// Create split listener
	w.workerAuthSplitListener, err = nodeenet.NewSplitListener(interceptingListener)
	if err != nil {
		return nil, fmt.Errorf("error instantiating split listener: %w", err)
	}

	// This handles connections coming in that are authenticated via
	// nodeenrollment but not with any extra purpose; these are normal PKI
	// worker connections
	nodeeAuthListener, err := w.workerAuthSplitListener.GetListener(nodeenet.AuthenticatedNonSpecificNextProto)
	if err != nil {
		return nil, fmt.Errorf("error instantiating worker split listener: %w", err)
	}

	// Connections that come into here are not authed by nodeenrollment so are
	// proxy connections
	proxyListener, err := w.workerAuthSplitListener.GetListener(nodeenet.UnauthenticatedNextProto)
	if err != nil {
		return nil, fmt.Errorf("error instantiating non-worker split listener: %w", err)
	}

	// Connections coming in here are authed by nodeenrollment and are for the
	// reverse grpc purpose
	reverseGrpcListener, err := w.workerAuthSplitListener.GetListener(common.ReverseGrpcConnectionAlpnValue)
	if err != nil {
		return nil, fmt.Errorf("error instantiating non-worker split listener: %w", err)
	}

	// This wraps the reverse grpc pki worker connections with a listener which
	// adds the worker key id of the connections to the worker's pkiConnManager.
	revPkiWorkerTrackingListener, err := cluster.NewTrackingListener(w.baseContext, reverseGrpcListener, w.pkiConnManager)
	if err != nil {
		return nil, fmt.Errorf("%s: error creating reverse grpc pki worker tracking listener: %w", op, err)
	}

	statsHandler, err := metric.InstrumentClusterStatsHandler(w.baseContext)
	if err != nil {
		return nil, errors.Wrap(w.baseContext, err, op)
	}
	downstreamServer := grpc.NewServer(
		grpc.StatsHandler(statsHandler),
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
	)

	for _, fn := range workerGrpcServiceRegistrationFunctions {
		if err := fn(cancelCtx, w, downstreamServer); err != nil {
			return nil, err
		}
	}

	metric.InitializeClusterServerCollectors(w.conf.PrometheusRegisterer, downstreamServer)

	ln.GrpcServer = downstreamServer

	eventingListener, err := common.NewEventingListener(cancelCtx, nodeeAuthListener)
	if err != nil {
		return nil, fmt.Errorf("%s: error creating eventing listener: %w", op, err)
	}

	// This wraps the normal pki worker connections with a listener which adds
	// the worker key id of the  connections to the worker's pkiConnManager.
	pkiWorkerTrackingListener, err := cluster.NewTrackingListener(cancelCtx, eventingListener, w.pkiConnManager)
	if err != nil {
		return nil, fmt.Errorf("%s: error creating pki worker tracking listener: %w", op, err)
	}

	return func() {
		go w.workerAuthSplitListener.Start()
		go httpServer.Serve(proxyListener)
		go ln.GrpcServer.Serve(pkiWorkerTrackingListener)
		go handleSecondaryConnection(cancelCtx, revPkiWorkerTrackingListener, w.downstreamRoutes, -1)
	}, nil
}

func (w *Worker) stopServersAndListeners() error {
	var mg multierror.Group
	mg.Go(w.stopHttpServer)
	mg.Go(w.stopClusterGrpcServer)

	stopErrors := mg.Wait()

	err := w.stopAnyListeners()
	if err != nil {
		stopErrors = multierror.Append(stopErrors, err)
	}

	return stopErrors.ErrorOrNil()
}

func (w *Worker) stopHttpServer() error {
	if w.proxyListener == nil {
		return nil
	}

	if w.proxyListener.HTTPServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(w.baseContext, w.proxyListener.Config.MaxRequestDuration)
	w.proxyListener.HTTPServer.Shutdown(ctx)
	cancel()

	return nil
}

func (w *Worker) stopClusterGrpcServer() error {
	if w.proxyListener == nil {
		return nil
	}
	if w.proxyListener.GrpcServer == nil {
		return nil
	}

	w.proxyListener.GrpcServer.GracefulStop()
	return nil
}

// stopAnyListeners does a final once over the known
// listeners to make sure we didn't miss any;
// expected to run at the end of stopServersAndListeners.
func (w *Worker) stopAnyListeners() error {
	if w.proxyListener == nil {
		return nil
	}
	if w.proxyListener.ProxyListener == nil {
		return nil
	}

	return listenerCloseErrorCheck("proxy", w.proxyListener.ProxyListener.Close())
}

// listenerCloseErrorCheck does some validation on an error returned
// by a net.Listener's Close function, and ignores a few cases
// where we don't actually want an error to be returned.
func listenerCloseErrorCheck(lnType string, err error) error {
	if errors.Is(err, net.ErrClosed) {
		// Ignore net.ErrClosed - The listener was already closed,
		// so there's nothing else to do.
		return nil
	}
	if _, ok := err.(*os.PathError); ok && lnType == "unix" {
		// The underlying rmListener probably tried to remove
		// the file but it didn't exist, ignore the error;
		// this is a conflict between rmListener and the
		// default Go behavior of removing auto-vivified
		// Unix domain sockets.
		return nil
	}

	return err
}
