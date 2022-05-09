package worker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/workers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-multierror"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"github.com/hashicorp/nodeenrollment/nodeauth"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"google.golang.org/grpc"
)

func (w *Worker) startListeners() error {
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

	workerServer, err := w.configureForWorker(w.proxyListener, logger)
	if err != nil {
		return fmt.Errorf("%s: failed to configure for worker: %w", op, err)
	}

	workerServer()

	return nil
}

func (w *Worker) configureForWorker(ln *base.ServerListener, logger *log.Logger) (func(), error) {
	handler, err := w.handler(HandlerProperties{ListenerConfig: ln.Config})
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
		req *nodetypes.FetchNodeCredentialsRequest,
		_ ...nodee.Option,
	) (*nodetypes.FetchNodeCredentialsResponse, error) {
		client := w.controllerMultihopConn.Load()
		if client == nil {
			return nil, nodeauth.NewTempError(errors.New("error fetching controller connection, client is nil"))
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, nodeauth.NewTempError(errors.New("client could not be understood as a multihop service client"))
		}
		return multihopClient.FetchNodeCredentials(ctx, req)
	}

	generateServerCertificatesFn := func(
		ctx context.Context,
		_ nodee.Storage,
		req *nodetypes.GenerateServerCertificatesRequest,
		_ ...nodee.Option,
	) (*nodetypes.GenerateServerCertificatesResponse, error) {
		client := w.controllerMultihopConn.Load()
		if client == nil {
			return nil, nodeauth.NewTempError(errors.New("error fetching controller connection, client is nil"))
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, nodeauth.NewTempError(errors.New("client could not be understood as a multihop service client"))
		}
		return multihopClient.GenerateServerCertificates(ctx, req)
	}

	interceptingListener, err := nodeauth.NewInterceptingListener(
		ln.ProxyListener,
		&tls.Config{
			GetConfigForClient: w.getSessionTls,
		},
		nodeauth.MakeCurrentParametersFactory(
			w.baseContext,
			nodee.NopTransactionStorage(w.NodeeFileStorage),
		),
		fetchCredsFn,
		generateServerCertificatesFn,
	)
	if err != nil {
		return nil, fmt.Errorf("error instantiating node auth listener: %w", err)
	}

	w.nodeeTeeListener = nodeauth.NewTeeListener(interceptingListener)

	downstreamServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
	)
	multihopService := workers.NewMultihopServiceServer(
		nodeauth.MakeCurrentParametersFactory(w.baseContext, nodee.NopTransactionStorage(w.NodeeFileStorage)),
	)
	multihop.RegisterMultihopServiceServer(downstreamServer, multihopService)
	statusSessionService := workers.NewWorkerProxyServiceServer(w.controllerStatusConn, w.controllerSessionConn)
	pbs.RegisterServerCoordinationServiceServer(downstreamServer, statusSessionService)
	pbs.RegisterSessionServiceServer(downstreamServer, statusSessionService)

	ln.GrpcServer = downstreamServer

	return func() {
		go w.nodeeTeeListener.Start()
		go httpServer.Serve(w.nodeeTeeListener.OtherListener())
		go ln.GrpcServer.Serve(w.nodeeTeeListener.NodeeListener())
	}, nil
}

func (w *Worker) stopServersAndListeners() error {
	var mg multierror.Group
	mg.Go(w.stopHttpServer)
	mg.Go(w.stopClusterGrpcServer)

	// FIXME (jeff): For some reason, unlike the controller, the grpc server
	// really likes to hang on closing. Maybe because it's never served a
	// connection? This is a workaround to force it until I can dig in.
	var cancel context.CancelFunc
	if w.nodeeTeeListener != nil {
		var ctx context.Context
		ctx, cancel = context.WithTimeout(w.baseContext, 2*time.Second)
		go func() {
			<-ctx.Done()
			w.nodeeTeeListener.Stop()
			cancel()
		}()
	}

	stopErrors := mg.Wait()

	if w.nodeeTeeListener != nil {
		cancel()
		err := w.nodeeTeeListener.Stop()
		if err != nil {
			stopErrors = multierror.Append(stopErrors, err)
		}
	}

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
	var closeErrors *multierror.Error
	var err error
	if w.nodeeTeeListener != nil {
		err = w.nodeeTeeListener.Stop()
	} else if w.proxyListener.ProxyListener != nil {
		err = w.proxyListener.ProxyListener.Close()
	}
	err = listenerCloseErrorCheck("proxy", err)
	if err != nil {
		closeErrors = multierror.Append(closeErrors, err)
	}

	return closeErrors.ErrorOrNil()
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
