package worker

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (c *Worker) startListeners() error {
	var retErr *multierror.Error
	servers := make([]func(), 0, len(c.conf.Listeners))

	configureClientConn := func(addr string) error {
		tlsConf, authInfo, err := c.workerAuthTLSConfig()
		if err != nil {
			return fmt.Errorf("error creating tls config for worker auth: %w", err)
		}

		cc, err := grpc.DialContext(c.baseContext, addr,
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
			grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)),
		)
		if err != nil {
			return fmt.Errorf("error dialing controller for worker auth: %w", err)
		}

		client := services.NewWorkerServiceClient(cc)
		c.controllerConns = append(c.controllerConns, client)

		authResponse, err := client.Authenticate(c.baseContext, &services.WorkerServiceAuthenticateRequest{
			Name:            c.conf.RawConfig.Worker.Name,
			ConnectionNonce: authInfo.ConnectionNonce,
		})
		if err != nil {
			return fmt.Errorf("error authenticating to controller for worker auth: %w", err)
		}
		if authResponse == nil || !authResponse.Success {
			return errors.New("error authenticating to controller for worker auth: unexpected response")
		}

		c.logger.Info("connected to controller", "address", addr)
		return nil
	}

	for _, ln := range c.conf.Listeners {
		var err error
		for _, purpose := range ln.Config.Purpose {
			switch purpose {
			case "api", "cluster":
				// Do nothing, in a dev mode we might see it here
			case "worker-alpn-tls":
				// TODO
			default:
				err = fmt.Errorf("unknown listener purpose %q", purpose)
			}
			if err != nil {
				break
			}
		}
		if err != nil {
			retErr = multierror.Append(retErr, err)
			continue
		}
	}

	// Break out early if we already hit errors
	if err := retErr.ErrorOrNil(); err != nil {
		return err
	}

	for _, addr := range c.conf.RawConfig.Worker.Controllers {
		host, port, err := net.SplitHostPort(addr)
		if err != nil && strings.Contains(err.Error(), "missing port in address") {
			host, port, err = net.SplitHostPort(fmt.Sprintf("%s:%s", addr, "9201"))
		}
		if err != nil {
			retErr = multierror.Append(retErr, err)
			continue
		}

		if err := configureClientConn(fmt.Sprintf("%s:%s", host, port)); err != nil {
			retErr = multierror.Append(retErr, err)
			continue
		}
	}

	if err := retErr.ErrorOrNil(); err != nil {
		return err
	}

	for _, s := range servers {
		s()
	}

	return nil
}

func (c *Worker) stopListeners() error {
	var retErr *multierror.Error
	for _, ln := range c.conf.Listeners {
		if ln.ALPNListener != nil {
			if err := ln.ALPNListener.Close(); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}

		if !c.conf.RawConfig.DevController {
			if err := ln.Mux.Close(); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}
	}
	return retErr.ErrorOrNil()
}
