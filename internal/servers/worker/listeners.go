package worker

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"google.golang.org/grpc"
)

func (c *Worker) controllerDialerFunc() func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		tlsConf, authInfo, err := c.workerAuthTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("error creating tls config for worker auth: %w", err)
		}
		dialer := &net.Dialer{}
		nonTlsConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("unable to dial to controller: %w", err)
		}
		tlsConn := tls.Client(nonTlsConn, tlsConf)
		written, err := tlsConn.Write([]byte(authInfo.ConnectionNonce))
		if err != nil {
			if err := nonTlsConn.Close(); err != nil {
				c.logger.Error("error closing connection after writing failure", "error", err)
			}
			return nil, fmt.Errorf("unable to write connection nonce: %w", err)
		}
		if written != len(authInfo.ConnectionNonce) {
			if err := nonTlsConn.Close(); err != nil {
				c.logger.Error("error closing connection after writing failure", "error", err)
			}
			return nil, fmt.Errorf("expected to write %d bytes of connection nonce, wrote %d", len(authInfo.ConnectionNonce), written)
		}
		return tlsConn, nil
	}
}

func (c *Worker) startListeners() error {
	var retErr *multierror.Error
	servers := make([]func(), 0, len(c.conf.Listeners))

	configureClientConn := func(addr string) error {
		cc, err := grpc.DialContext(c.baseContext, addr,
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
			grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
			grpc.WithContextDialer(c.controllerDialerFunc()),
			grpc.WithInsecure(),
		)
		if err != nil {
			return fmt.Errorf("error dialing controller for worker auth: %w", err)
		}

		client := services.NewWorkerServiceClient(cc)
		c.controllerConns = append(c.controllerConns, client)

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
