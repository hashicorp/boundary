package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/internal/metric"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-multierror"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
	"github.com/hashicorp/nodeenrollment/protocol"
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

func (c *Controller) startListeners() error {
	servers := make([]func(), 0, len(c.conf.Listeners))

	grpcServer, gwTicket, err := newGrpcServer(c.baseContext, c.IamRepoFn, c.AuthTokenRepoFn, c.ServersRepoFn, c.PasswordAuthRepoFn, c.OidcRepoFn, c.kms, c.conf.Eventer)
	if err != nil {
		return fmt.Errorf("failed to create new grpc server: %w", err)
	}
	c.apiGrpcServer = grpcServer
	c.apiGrpcGatewayTicket = gwTicket

	err = c.registerGrpcServices(c.apiGrpcServer)
	if err != nil {
		return fmt.Errorf("failed to register grpc services: %w", err)
	}

	c.apiGrpcServerListener = newGrpcServerListener()
	servers = append(servers, func() {
		go c.apiGrpcServer.Serve(c.apiGrpcServerListener)
	})

	for i := range c.apiListeners {
		ln := c.apiListeners[i]
		apiServers, err := c.configureForApi(ln)
		if err != nil {
			return fmt.Errorf("failed to configure listener for api mode: %w", err)
		}
		servers = append(servers, apiServers...)
	}

	clusterServer, err := c.configureForCluster(c.clusterListener)
	if err != nil {
		return fmt.Errorf("failed to configure listener for cluster mode: %w", err)
	}
	servers = append(servers, clusterServer)

	for _, s := range servers {
		s()
	}

	return nil
}

func (c *Controller) configureForApi(ln *base.ServerListener) ([]func(), error) {
	apiServers := make([]func(), 0)

	handler, err := c.apiHandler(HandlerProperties{
		ListenerConfig: ln.Config,
		CancelCtx:      c.baseContext,
	})
	if err != nil {
		return nil, err
	}

	cancelCtx := c.baseContext // Resolve to avoid race conditions if the base context is replaced.
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ErrorLog:          c.logger.StandardLogger(nil),
		BaseContext:       func(net.Listener) context.Context { return cancelCtx },
	}
	ln.HTTPServer = server

	if ln.Config.HTTPReadHeaderTimeout > 0 {
		server.ReadHeaderTimeout = ln.Config.HTTPReadHeaderTimeout
	}
	if ln.Config.HTTPReadTimeout > 0 {
		server.ReadTimeout = ln.Config.HTTPReadTimeout
	}
	if ln.Config.HTTPWriteTimeout > 0 {
		server.WriteTimeout = ln.Config.HTTPWriteTimeout
	}
	if ln.Config.HTTPIdleTimeout > 0 {
		server.IdleTimeout = ln.Config.HTTPIdleTimeout
	}

	apiServers = append(apiServers, func() { go server.Serve(ln.ApiListener) })

	return apiServers, nil
}

func (c *Controller) configureForCluster(ln *base.ServerListener) (func(), error) {
	const op = "controller.configureForCluster"

	workerAuthStorage, err := c.WorkerAuthRepoStorageFn()
	if err != nil {
		return nil, fmt.Errorf("error fetching worker auth storage: %w", err)
	}

	// The cluster listener is shut down at server shutdown time so we do not
	// need to handle individual listener shutdown.
	var l net.Listener
	l, err = protocol.NewInterceptingListener(
		&protocol.InterceptingListenerConfiguration{
			Context:      c.baseContext,
			Storage:      workerAuthStorage,
			BaseListener: ln.ClusterListener,
			BaseTlsConfiguration: &tls.Config{
				GetConfigForClient: c.validateWorkerTls,
			},
		})
	if err != nil {
		return nil, fmt.Errorf("error instantiating node auth listener: %w", err)
	}

	// Create split listener
	splitListener, err := nodeenet.NewSplitListener(l)
	if err != nil {
		return nil, fmt.Errorf("error instantiating split listener: %w", err)
	}

	// This handles connections coming in on the cluster port that are
	// authenticated via nodeenrollment but not with any extra purpose; these
	// are normal worker connections
	nodeeAuthedListener, err := splitListener.GetListener(nodeenet.AuthenticatedNonSpecificNextProto)
	if err != nil {
		return nil, fmt.Errorf("error instantiating node enrollment authed split listener: %w", err)
	}
	// This wraps the normal worker connections with something that events with
	// the worker ID on successful auth/connection
	eventingAuthedListener, err := common.NewEventingListener(c.baseContext, nodeeAuthedListener)
	if err != nil {
		return nil, fmt.Errorf("%s: error creating eventing listener: %w", op, err)
	}
	// Create a multiplexer to unify connections between PKI and KMS
	multiplexingAuthedListener, err := nodeenet.NewMultiplexingListener(c.baseContext, nodeeAuthedListener.Addr())
	if err != nil {
		return nil, fmt.Errorf("error instantiating authed multiplexed listener: %w", err)
	}
	if err := multiplexingAuthedListener.IngressListener(eventingAuthedListener); err != nil {
		return nil, fmt.Errorf("error adding authed evented listener to multiplexed listener: %w", err)
	}
	// Connections that came in on the cluster listener that are not authed via
	// PKI need to be sent for KMS routing
	nodeeUnauthedListener, err := splitListener.GetListener(nodeenet.UnauthenticatedNextProto)
	if err != nil {
		return nil, fmt.Errorf("error instantiating node enrollment unauthed split listener: %w", err)
	}

	// Connections coming in here are authed by nodeenrollment and are for the
	// reverse grpc purpose
	reverseGrpcListener, err := splitListener.GetListener(common.ReverseGrpcConnectionAlpnValue)
	if err != nil {
		return nil, fmt.Errorf("error instantiating reverse gprc connection split listener: %w", err)
	}
	// Create a multiplexer to unify reverse grpc connections between PKI and KMS
	multiplexingReverseGrpcListener, err := nodeenet.NewMultiplexingListener(c.baseContext, reverseGrpcListener.Addr())
	if err != nil {
		return nil, fmt.Errorf("error instantiating reverse grpc multiplexed listener: %w", err)
	}
	if err := multiplexingReverseGrpcListener.IngressListener(reverseGrpcListener); err != nil {
		return nil, fmt.Errorf("error adding reverse grpc listener to multiplexed listener: %w", err)
	}

	// Start routing KMS connections
	if err := startKmsConnRouter(c.baseContext, c, nodeeUnauthedListener, multiplexingAuthedListener, multiplexingReverseGrpcListener); err != nil {
		return nil, errors.Wrap(c.baseContext, err, op)
	}

	workerReqInterceptor, err := workerRequestInfoInterceptor(c.baseContext, c.conf.Eventer)
	if err != nil {
		return nil, fmt.Errorf("error getting request interceptor for worker proto: %w", err)
	}
	statsHandler, err := metric.InstrumentClusterStatsHandler(c.baseContext)
	if err != nil {
		return nil, errors.Wrap(c.baseContext, err, op)
	}

	workerServer := grpc.NewServer(
		grpc.StatsHandler(statsHandler),
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				workerReqInterceptor,
				auditRequestInterceptor(c.baseContext),  // before we get started, audit the request
				auditResponseInterceptor(c.baseContext), // as we finish, audit the response
			),
		),
	)

	for _, fn := range controllerGrpcServiceRegistrationFunctions {
		if err := fn(c.baseContext, c, workerServer); err != nil {
			return nil, err
		}
	}

	metric.InitializeClusterCollectors(c.conf.PrometheusRegisterer, workerServer)

	ln.GrpcServer = workerServer

	return func() {
		go func() {
			err := splitListener.Start()
			if err != nil {
				event.WriteError(c.baseContext, op, err, event.WithInfoMsg("splitListener.Start() error"))
			}
		}()
		go func() {
			err := handleSecondaryConnection(c.baseContext, multiplexingReverseGrpcListener, c.downstreamRoutes, -1)
			if err != nil {
				event.WriteError(c.baseContext, op, err, event.WithInfoMsg("handleSecondaryConnection error"))
			}
		}()
		go func() {
			err := ln.GrpcServer.Serve(multiplexingAuthedListener)
			if err != nil {
				event.WriteError(c.baseContext, op, err, event.WithInfoMsg("multiplexingAuthedListener error"))
			}
		}()
	}, nil
}

func (c *Controller) stopServersAndListeners() error {
	var mg multierror.Group
	mg.Go(c.stopClusterGrpcServerAndListener)
	mg.Go(c.stopHttpServersAndListeners)
	mg.Go(c.stopApiGrpcServerAndListener)

	stopErrors := mg.Wait()

	err := c.stopAnyListeners()
	if err != nil {
		stopErrors = multierror.Append(stopErrors, err)
	}

	return stopErrors.ErrorOrNil()
}

func (c *Controller) stopClusterGrpcServerAndListener() error {
	if c.clusterListener == nil {
		return nil
	}
	if c.clusterListener.GrpcServer == nil {
		return fmt.Errorf("no cluster grpc server")
	}
	if c.clusterListener.ClusterListener == nil {
		return fmt.Errorf("no cluster listener")
	}

	c.clusterListener.GrpcServer.GracefulStop()
	err := c.clusterListener.ClusterListener.Close()
	return listenerCloseErrorCheck(c.clusterListener.Config.Type, err)
}

func (c *Controller) stopHttpServersAndListeners() error {
	var closeErrors *multierror.Error
	for i := range c.apiListeners {
		ln := c.apiListeners[i]
		if ln.HTTPServer == nil {
			continue
		}

		ctx, cancel := context.WithTimeout(c.baseContext, ln.Config.MaxRequestDuration)
		ln.HTTPServer.Shutdown(ctx)
		cancel()

		err := ln.ApiListener.Close() // The HTTP Shutdown call should close this, but just in case.
		err = listenerCloseErrorCheck(ln.Config.Type, err)
		if err != nil {
			multierror.Append(closeErrors, err)
		}
	}

	return closeErrors.ErrorOrNil()
}

func (c *Controller) stopApiGrpcServerAndListener() error {
	if c.apiGrpcServer == nil {
		return nil
	}

	c.apiGrpcServer.GracefulStop()
	err := c.apiGrpcServerListener.Close()
	return listenerCloseErrorCheck("ch", err) // apiGrpcServerListener is just a channel, so the type here is not important.
}

// stopAnyListeners does a final once over the known
// listeners to make sure we didn't miss any;
// expected to run at the end of stopServersAndListeners.
func (c *Controller) stopAnyListeners() error {
	var closeErrors *multierror.Error
	for i := range c.apiListeners {
		ln := c.apiListeners[i]
		if ln == nil || ln.ApiListener == nil {
			continue
		}

		err := ln.ApiListener.Close()
		err = listenerCloseErrorCheck(ln.Config.Type, err)
		if err != nil {
			multierror.Append(closeErrors, err)
		}
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
