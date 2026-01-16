// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"crypto/tls"
	stderrors "errors"
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
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-multierror"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
	"github.com/hashicorp/nodeenrollment/protocol"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/hashicorp/nodeenrollment/util/temperror"
	"github.com/hashicorp/nodeenrollment/util/toggledlogger"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	// the purpose strings used to identify listeners
	reverseGrpcListenerPurpose            = "reverse-grpc"
	multihopProxyDataplaneListenerPurpose = "multihop-proxy-dataplane"
	grpcListenerPurpose                   = "grpc"
)

// the function that handles a secondary connection over a provided listener
var handleSecondaryConnection = closeListeners

// closeListeners handles the secondary connection listeners by closing them.
// l is the grpc listener and l2 is the data plane listener.
func closeListeners(_ context.Context, l, l2 net.Listener, _ any) error {
	if l != nil {
		l.Close()
	}
	if l2 != nil {
		l2.Close()
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
		storage nodee.Storage,
		req *types.FetchNodeCredentialsRequest,
		opt ...nodee.Option,
	) (*types.FetchNodeCredentialsResponse, error) {
		switch {
		case req == nil:
			return nil, temperror.New(stderrors.New("nil request in multi-hop fetch function"))
		case len(req.Bundle) == 0:
			return nil, temperror.New(stderrors.New("empty bundle in multi-hop fetch function"))
		}
		// Check to see if there is encrypted registration info, if so we need
		// to use our wrapper to decrypt it
		reqInfo := new(types.FetchNodeCredentialsInfo)
		if err := proto.Unmarshal(req.Bundle, reqInfo); err != nil {
			return nil, temperror.New(fmt.Errorf("error unmarshaling request bundle in multi-hop fetch function: %w", err))
		}
		if len(reqInfo.WrappedRegistrationInfo) > 0 {
			regInfo, err := registration.DecryptWrappedRegistrationInfo(ctx, reqInfo, opt...)
			if err != nil {
				return nil, temperror.New(fmt.Errorf("error during decryption of wrapped registration info in multi-hop fetch function: %w", err))
			}
			// We've successfully decrypted it using our registration wrapper;
			// now we need to encrypt it to the server
			nodeCreds, err := types.LoadNodeCredentials(ctx, storage, nodee.CurrentId, opt...)
			if err != nil {
				return nil, temperror.New(fmt.Errorf("error loading node credentials in multi-hop fetch function: %w", err))
			}
			req.RewrappingKeyId, err = nodee.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
			if err != nil {
				return nil, temperror.New(fmt.Errorf("error deriving node credentials key id in multi-hop fetch function: %w", err))
			}
			req.RewrappedWrappingRegistrationFlowInfo, err = nodee.EncryptMessage(ctx, regInfo, nodeCreds)
			if err != nil {
				return nil, temperror.New(fmt.Errorf("error rewrapping registration information in multi-hop fetch function: %w", err))
			}
		}
		client := w.controllerMultihopConn.Load()
		if client == nil {
			return nil, temperror.New(stderrors.New("error fetching controller connection, client is nil"))
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, temperror.New(stderrors.New("client could not be understood as a multihop service client"))
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
			return nil, temperror.New(stderrors.New("error fetching controller connection, client is nil"))
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, temperror.New(stderrors.New("client could not be understood as a multihop service client"))
		}
		return multihopClient.GenerateServerCertificates(ctx, req)
	}

	eventLogger, err := event.NewHclogLogger(w.baseContext, w.conf.Eventer)
	if err != nil {
		event.WriteError(w.baseContext, op, err)
		return nil, errors.Wrap(w.baseContext, err, op)
	}
	// Give the log a prefix
	eventLogger = eventLogger.Named(fmt.Sprintf("workerauth_listener"))
	// Wrap the log in a toggle so we can turn it on and off via config and
	// SIGHUP
	eventLogger = toggledlogger.NewToggledLogger(eventLogger, w.conf.WorkerAuthDebuggingEnabled)

	wrapperToUse := w.conf.WorkerAuthKms
	if !util.IsNil(w.conf.DownstreamWorkerAuthKms) {
		wrapperToUse = w.conf.DownstreamWorkerAuthKms
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
			Options: []nodee.Option{
				nodee.WithStorageWrapper(w.conf.WorkerAuthStorageKms),
				nodee.WithRegistrationWrapper(wrapperToUse),
				nodee.WithLogger(eventLogger),
			},
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
	// nodeenrollment but not with any extra purpose; these are normal worker
	// connections
	nodeeAuthListener, err := w.workerAuthSplitListener.GetListener(nodeenet.AuthenticatedNonSpecificNextProto, nodee.WithNativeConns(true))
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
	reverseGrpcListener, err := w.workerAuthSplitListener.GetListener(common.ReverseGrpcConnectionAlpnValue, nodee.WithNativeConns(true))
	if err != nil {
		return nil, fmt.Errorf("error instantiating reverse grpc split listener: %w", err)
	}

	// This wraps the reverse grpc worker connections with a listener which adds
	// the worker key id of the connections to the worker's downstream
	// ConnManager.
	revWorkerTrackingListener, err := cluster.NewTrackingListener(w.baseContext, reverseGrpcListener, w.downstreamConnManager, sourcePurpose(reverseGrpcListenerPurpose))
	if err != nil {
		return nil, fmt.Errorf("%s: error creating reverse grpc worker tracking listener: %w", op, err)
	}

	// Connections coming in here are authed by nodeenrollment and are for the
	// multi-hop session-proxying
	dataPlaneProxyListener, err := w.workerAuthSplitListener.GetListener(common.DataPlaneProxyAlpnValue, nodee.WithNativeConns(true))
	if err != nil {
		return nil, fmt.Errorf("error instantiating websocket proxying split listener: %w", err)
	}

	// This wraps the web socket proxying worker connections with a listener which
	// adds the worker key id of the connections to the worker's downstreamConnManager.
	dataPlaneProxyTrackingListener, err := cluster.NewTrackingListener(w.baseContext, dataPlaneProxyListener, w.downstreamConnManager, sourcePurpose(multihopProxyDataplaneListenerPurpose))
	if err != nil {
		return nil, fmt.Errorf("%s: error creating websocket proxying tracking listener: %w", op, err)
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

	metric.InitializeConnectionCounters(w.conf.PrometheusRegisterer)
	metric.InitializeClusterServerCollectors(w.conf.PrometheusRegisterer, downstreamServer)

	ln.GrpcServer = downstreamServer

	// This wraps the normal worker connections with a listener which adds the
	// worker key id of the connections to the worker's downstreamConnManager.
	workerTrackingListener, err := cluster.NewTrackingListener(cancelCtx, nodeeAuthListener, w.downstreamConnManager, sourcePurpose(grpcListenerPurpose))
	if err != nil {
		return nil, fmt.Errorf("%s: error creating worker tracking listener: %w", op, err)
	}

	return func() {
		handleSecondaryConnection(cancelCtx, metric.InstrumentWorkerClusterTrackingListener(revWorkerTrackingListener, reverseGrpcListenerPurpose),
			metric.InstrumentWorkerClusterTrackingListener(dataPlaneProxyTrackingListener, multihopProxyDataplaneListenerPurpose), w.downstreamReceiver)
		go w.workerAuthSplitListener.Start()
		go httpServer.Serve(proxyListener)
		go ln.GrpcServer.Serve(metric.InstrumentWorkerClusterTrackingListener(workerTrackingListener, grpcListenerPurpose))
	}, nil
}

func (w *Worker) stopServersAndListeners() error {
	var mg multierror.Group
	mg.Go(w.stopHttpServer)
	mg.Go(w.stopClusterGrpcServer)

	stopErrors := mg.Wait()
	convertedStopErrors := stopErrors.ErrorOrNil()

	err := w.stopAnyListeners()
	if err != nil {
		convertedStopErrors = stderrors.Join(convertedStopErrors, err)
	}

	return convertedStopErrors
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

func sourcePurpose(purpose string) string {
	return fmt.Sprintf("worker %s", purpose)
}
