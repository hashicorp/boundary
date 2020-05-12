package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-alpnmux"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/watchtower/internal/cmd/base"
)

func (c *Controller) startListeners() error {
	var retErr *multierror.Error
	servers := make([]func(), 0, len(c.conf.Listeners))

	configureForAPI := func(ln *base.ServerListener) error {
		handler := Handler(c, HandlerProperties{
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
			ErrorLog:          c.logger.StandardLogger(nil),
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
				return errors.New("could not get non-tls listener")
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

		return nil
	}

	configureForCluster := func(ln *base.ServerListener) error {
		l, err := ln.Mux.RegisterProto(alpnmux.DefaultProto, &tls.Config{
			GetConfigForClient: c.validateWorkerTLS,
		})
		if err != nil {
			return fmt.Errorf("error getting sub-listener for worker proto: %w", err)
		}
		ln.ALPNListener = l

		// TODO: Pass this to a handler, e.g. a grpc server, in the mean time
		// just accepting what comes
		go func() {
			for {
				conn, err := ln.ALPNListener.Accept()
				if err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						c.logger.Info("default alpn listener errored, exiting", "error", err)
					}
					return
				}
				_, err = conn.Read(make([]byte, 3))
				if err != nil {
					retErr = multierror.Append(retErr, fmt.Errorf("error reading test string from worker for worker auth: %w", err))
				}
				_, err = conn.Write([]byte("bar"))
				if err != nil {
					retErr = multierror.Append(retErr, fmt.Errorf("error writing test string to worker for worker auth: %w", err))
				}
				conn.Close()
			}
		}()
		return nil
	}

	for _, ln := range c.conf.Listeners {
		var err error
		for _, purpose := range ln.Config.Purpose {
			switch purpose {
			case "api":
				err = configureForAPI(ln)
			case "cluster":
				err = configureForCluster(ln)
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

	err := retErr.ErrorOrNil()
	if err != nil {
		return err
	}

	for _, s := range servers {
		s()
	}

	return nil
}

func (c *Controller) stopListeners() error {
	serverWg := new(sync.WaitGroup)
	for _, ln := range c.conf.Listeners {
		if ln.HTTPServer == nil {
			continue
		}
		localLn := ln
		serverWg.Add(1)
		go func() {
			shutdownKill, shutdownKillCancel := context.WithTimeout(c.baseContext, localLn.Config.MaxRequestDuration)
			defer shutdownKillCancel()
			defer serverWg.Done()
			localLn.HTTPServer.Shutdown(shutdownKill)
		}()
	}
	serverWg.Wait()

	var retErr *multierror.Error
	for _, ln := range c.conf.Listeners {
		if err := ln.Mux.Close(); err != nil {
			retErr = multierror.Append(retErr, err)
		}
	}
	return retErr.ErrorOrNil()
}
