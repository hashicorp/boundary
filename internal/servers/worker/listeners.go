package worker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-alpnmux"
	"github.com/hashicorp/go-multierror"
)

func (w *Worker) startListeners() error {
	servers := make([]func(), 0, len(w.conf.Listeners))

	for _, ln := range w.conf.Listeners {
		for _, purpose := range ln.Config.Purpose {
			switch purpose {
			case "api", "cluster":
				// We may have this in dev mode; ignore
				continue

			case "worker-alpn-tls":
				// Do nothing; handle below

			default:
				return fmt.Errorf("unknown listener purpose %q", purpose)
			}

			if w.listeningAddress != "" {
				return errors.New("more than one listening address found")
			}

			handler := w.handler(HandlerProperties{
				ListenerConfig: ln.Config,
			})

			cancelCtx := w.baseContext

			server := &http.Server{
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				IdleTimeout:       5 * time.Minute,
				ErrorLog:          w.logger.StandardLogger(nil),
				BaseContext: func(net.Listener) context.Context {
					return cancelCtx
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

			// Clear out in case this is a second start of the controller
			ln.Mux.UnregisterProto(alpnmux.DefaultProto)
			ln.Mux.UnregisterProto(alpnmux.NoProto)
			l, err := ln.Mux.RegisterProto(alpnmux.DefaultProto, &tls.Config{
				GetConfigForClient: w.getJobTls,
			})
			if err != nil {
				return fmt.Errorf("error getting tls listener: %w", err)
			}
			if l == nil {
				return errors.New("could not get tls listener")
			}

			servers = append(servers, func() {
				go server.Serve(l)
			})

			if w.listeningAddress == "" {
				w.listeningAddress = l.Addr().String()
				w.logger.Info("reporting listening address to controllers", "address", w.listeningAddress)
			}
		}
	}

	for _, s := range servers {
		s()
	}

	return nil
}

func (w *Worker) stopListeners() error {
	serverWg := new(sync.WaitGroup)
	for _, ln := range w.conf.Listeners {
		localLn := ln
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()

			shutdownKill, shutdownKillCancel := context.WithTimeout(w.baseContext, localLn.Config.MaxRequestDuration)
			defer shutdownKillCancel()

			if localLn.HTTPServer != nil {
				localLn.HTTPServer.Shutdown(shutdownKill)
			}
		}()
	}
	serverWg.Wait()

	var retErr *multierror.Error
	if !w.conf.RawConfig.DevController {
		for _, ln := range w.conf.Listeners {
			if err := ln.Mux.Close(); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}
	}
	return retErr.ErrorOrNil()
}
