package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/hashicorp/boundary/internal/cmd/base"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/libs/alpnmux"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/workers"
	"github.com/hashicorp/go-multierror"
	"google.golang.org/grpc"
)

func (c *Controller) startListeners() error {
	servers := make([]func(), 0, len(c.conf.Listeners))

	grpcServer, gwTicket, err := newGrpcServer(c.baseContext, c.IamRepoFn, c.AuthTokenRepoFn, c.ServersRepoFn, c.kms, c.conf.Eventer)
	if err != nil {
		return fmt.Errorf("failed to create new grpc server: %w", err)
	}
	c.apiGrpcServer = grpcServer
	c.apiGrpcGatewayTicket = gwTicket

	err = c.registerGrpcServices(c.baseContext, c.apiGrpcServer)
	if err != nil {
		return fmt.Errorf("failed to register grpc services: %w", err)
	}

	c.apiGrpcServerListener = newGrpcServerListener()
	servers = append(servers, func() {
		go c.apiGrpcServer.Serve(c.apiGrpcServerListener)
	})

	for i := range c.apiListeners {
		ln := c.apiListeners[i]
		apiServers, err := c.configureForAPI(ln)
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

func (c *Controller) configureForAPI(ln *base.ServerListener) ([]func(), error) {
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

	switch ln.Config.TLSDisable {
	case true:
		l, err := ln.Mux.RegisterProto(alpnmux.NoProto, nil)
		if err != nil {
			return nil, fmt.Errorf("error getting non-tls listener: %w", err)
		}
		if l == nil {
			return nil, errors.New("could not get non-tls listener")
		}
		apiServers = append(apiServers, func() { go server.Serve(l) })

	default:
		for _, v := range []string{"", "http/1.1", "h2"} {
			l := ln.Mux.GetListener(v)
			if l == nil {
				return nil, fmt.Errorf("could not get tls proto %q listener", v)
			}
			apiServers = append(apiServers, func() { go server.Serve(l) })
		}
	}

	return apiServers, nil
}

func (c *Controller) configureForCluster(ln *base.ServerListener) (func(), error) {
	// Clear out in case this is a second start of the controller
	ln.Mux.UnregisterProto(alpnmux.DefaultProto)
	l, err := ln.Mux.RegisterProto(alpnmux.DefaultProto, &tls.Config{
		GetConfigForClient: c.validateWorkerTls,
	})
	if err != nil {
		return nil, fmt.Errorf("error getting sub-listener for worker proto: %w", err)
	}

	workerReqInterceptor, err := workerRequestInfoInterceptor(c.baseContext, c.conf.Eventer)
	if err != nil {
		return nil, fmt.Errorf("error getting sub-listener for worker proto: %w", err)
	}

	workerServer := grpc.NewServer(
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

	workerService := workers.NewWorkerServiceServer(c.ServersRepoFn, c.SessionRepoFn, c.workerStatusUpdateTimes, c.kms)
	pbs.RegisterServerCoordinationServiceServer(workerServer, workerService)
	pbs.RegisterSessionServiceServer(workerServer, workerService)

	interceptor := newInterceptingListener(c, l)
	ln.ALPNListener = interceptor
	ln.GrpcServer = workerServer

	return func() { go ln.GrpcServer.Serve(ln.ALPNListener) }, nil
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
	if c.clusterListener.Mux == nil {
		return fmt.Errorf("no cluster listener mux")
	}

	c.clusterListener.GrpcServer.GracefulStop()
	err := c.clusterListener.Mux.Close()
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

		err := ln.Mux.Close() // The HTTP Shutdown call should close this, but just in case.
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
		if ln == nil || ln.Mux == nil {
			continue
		}

		err := ln.Mux.Close()
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
