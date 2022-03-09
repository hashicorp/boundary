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
	"sync"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/hashicorp/boundary/globals"
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

func (c *Controller) stopListeners(serversOnly bool) error {
	serverWg := new(sync.WaitGroup)
	for _, ln := range c.conf.Listeners {
		localLn := ln
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()

			shutdownKill, shutdownKillCancel := context.WithTimeout(c.baseContext, localLn.Config.MaxRequestDuration)
			defer shutdownKillCancel()

			if localLn.GrpcServer != nil {
				// Deal with the worst case
				go func() {
					<-shutdownKill.Done()
					localLn.GrpcServer.Stop()
				}()
				localLn.GrpcServer.GracefulStop()
			}
			if localLn.HTTPServer != nil {
				localLn.HTTPServer.Shutdown(shutdownKill)
			}
		}()
	}

	if c.apiGrpcServer != nil {
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			shutdownKill, shutdownKillCancel := context.WithTimeout(c.baseContext, globals.DefaultMaxRequestDuration)
			defer shutdownKillCancel()
			go func() {
				<-shutdownKill.Done()
				c.apiGrpcServer.Stop()
			}()
			c.apiGrpcServer.GracefulStop()
		}()
	}

	serverWg.Wait()
	if serversOnly {
		return nil
	}
	var retErr *multierror.Error
	for _, ln := range c.conf.Listeners {
		if err := ln.Mux.Close(); err != nil {
			if _, ok := err.(*os.PathError); ok && ln.Config.Type == "unix" {
				// The rmListener probably tried to remove the file but it
				// didn't exist, ignore the error; this is a conflict
				// between rmListener and the default Go behavior of
				// removing auto-vivified Unix domain sockets.
			} else {
				retErr = multierror.Append(retErr, err)
			}
		}
	}
	return retErr.ErrorOrNil()
}
