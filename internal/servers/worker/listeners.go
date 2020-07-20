package worker

import (
	"errors"
	"fmt"
	"math"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (c *Worker) startListeners() error {
	var retErr *multierror.Error
	servers := make([]func(), 0, len(c.conf.Listeners))
	for _, ln := range c.conf.Listeners {
		switch c.conf.RawConfig.DevController {
		case false:
			// TODO: We'll eventually need to configure HTTP listening here for
			// org-provided certificate handling, and configure the mux's
			// defaultproto for accepting client connections for ALPN-based
			// auth

		default:
			// TODO: We'll need to go through any listeners marked for api
			// usage and add our websocket handlers to the server. Eventually
			// we may want to make the config function able to handle arbitrary
			// ALPNs in a dynamic way, so that in dev mode we can also register
			// alpn mode client auth handling via the cluster ports.
			// TODO again because...I like that idea and don't want to forget
			// about it :-)
			// For now just testing out the ability to authorize via the ALPN handler
			if strutil.StrListContains(ln.Config.Purpose, "cluster") {
				tlsConf, authInfo, err := c.workerAuthTLSConfig()
				if err != nil {
					retErr = multierror.Append(retErr, fmt.Errorf("error creating tls config for worker auth: %w", err))
					continue
				}

				switch {
				case ln.ALPNListener != nil:
					cc, err := grpc.DialContext(c.baseContext, ln.ALPNListener.Addr().String(),
						grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
						grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
						grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)),
					)
					if err != nil {
						retErr = multierror.Append(retErr, fmt.Errorf("error dialing controller for worker auth: %w", err))
						continue
					}

					client := services.NewWorkerServiceClient(cc)
					c.controllerConns = append(c.controllerConns, client)

					authResponse, err := client.Authenticate(c.baseContext, &services.WorkerServiceAuthenticateRequest{
						Name:            c.conf.RawConfig.Worker.Name,
						ConnectionNonce: authInfo.ConnectionNonce,
					})
					if err != nil {
						retErr = multierror.Append(retErr, fmt.Errorf("error authenticating to controller for worker auth: %w", err))
						continue
					}
					if authResponse == nil || !authResponse.Success {
						retErr = multierror.Append(retErr, errors.New("error authenticating to controller for worker auth: unexpected response"))
						continue
					}
					c.logger.Info("connected to controller")

				default:
					return errors.New("no alpnmuxer found")
				}
			}
		}
	}

	err := retErr.ErrorOrNil()
	if err != nil {
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
