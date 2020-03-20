package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-alpnmux"
	"github.com/hashicorp/go-multierror"
)

func (c *Worker) startListeners() error {
	var retErr *multierror.Error
	servers := make([]func(), 0, len(c.conf.Listeners))
	for _, ln := range c.conf.Listeners {
		switch c.conf.RawConfig.DevController {
		case false:
			handler := c.Handler(HandlerProperties{
				ListenerConfig: ln.Config,
			})

			/*
				// TODO: As I write this Vault's having this code audited, make sure to
				// port over any recommendations
				//
				// We perform validation on the config earlier, we can just cast here
				if _, ok := ln.config["x_forwarded_for_authorized_addrs"]; ok {
					hopSkips := ln.config["x_forwarded_for_hop_skips"].(int)
					authzdAddrs := ln.config["x_forwarded_for_authorized_addrs"].([]*sockaddr.SockAddrMarshaler)
					rejectNotPresent := ln.config["x_forwarded_for_reject_not_present"].(bool)
					rejectNonAuthz := ln.config["x_forwarded_for_reject_not_authorized"].(bool)
					if len(authzdAddrs) > 0 {
						handler = vaulthttp.WrapForwardedForHandler(handler, authzdAddrs, rejectNotPresent, rejectNonAuthz, hopSkips)
					}
				}
			*/

			server := &http.Server{
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				IdleTimeout:       5 * time.Minute,
				ErrorLog:          c.conf.Logger.StandardLogger(nil),
				BaseContext: func(net.Listener) context.Context {
					return c.baseContext
				},
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
				l := ln.Mux.GetListener(alpnmux.NoProto)
				if l == nil {
					retErr = multierror.Append(retErr, errors.New("could not get non-tls listener"))
					continue
				}
				servers = append(servers, func() {
					go server.Serve(l)
				})

			default:
				protos := []string{"", "http/1.1", "h2"}
				for _, v := range protos {
					l := ln.Mux.GetListener(v)
					if l == nil {
						retErr = multierror.Append(retErr, fmt.Errorf("could not get tls proto %q listener", v))
						continue
					}
					servers = append(servers, func() {
						go server.Serve(l)
					})
				}
			}

			fallthrough

		default:
			if !ln.Config.TLSDisable {
				l := ln.Mux.GetListener(alpnmux.DefaultProto)
				if l == nil {
					retErr = multierror.Append(retErr, fmt.Errorf("could not get tls proto %q listener", alpnmux.DefaultProto))
					continue
				}
				ln.ALPNListener = l
				// TODO: give this listener to a server to handle ALPN auth
			}
			// TODO: Register websocket handler against server on this listener
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
	serverWg := new(sync.WaitGroup)
	for _, ln := range c.conf.Listeners {
		if c.conf.RawConfig.DevController {
			// These will get closed by the controller's dev instance
			continue
		}

		if ln.HTTPServer == nil {
			continue
		}
		serverWg.Add(1)
		go func() {
			shutdownKill, shutdownKillCancel := context.WithTimeout(c.baseContext, ln.Config.MaxRequestDuration)
			defer shutdownKillCancel()
			defer serverWg.Done()
			ln.HTTPServer.Shutdown(shutdownKill)
		}()
	}
	serverWg.Wait()

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
