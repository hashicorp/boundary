package worker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/libs/alpnmux"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-multierror"
)

func (w *Worker) startListeners() error {
	const op = "worker.(Worker).startListeners"

	e := event.SysEventer()
	if e == nil {
		return fmt.Errorf("%s: sys eventer not initialized", op)
	}
	logger, err := e.StandardLogger(w.baseContext, "listeners", event.ErrorType)
	if err != nil {
		return fmt.Errorf("%s: unable to initialize std logger: %w", op, err)
	}

	servers := make([]func(), 0, len(w.listeners))
	for i := range w.listeners {
		ln := w.listeners[i]
		workerServer, err := w.configureForWorker(ln, logger)
		if err != nil {
			return fmt.Errorf("%s: failed to configure for worker: %w", op, err)
		}
		servers = append(servers, workerServer)
	}

	for _, s := range servers {
		s()
	}

	return nil
}

func (w *Worker) configureForWorker(ln *base.ServerListener, log *log.Logger) (func(), error) {
	handler, err := w.handler(HandlerProperties{ListenerConfig: ln.Config})
	if err != nil {
		return nil, err
	}

	cancelCtx := w.baseContext
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		ErrorLog:          log,
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
		GetConfigForClient: w.getSessionTls,
	})
	if err != nil {
		return nil, fmt.Errorf("error getting tls listener: %w", err)
	}
	if l == nil {
		return nil, errors.New("could not get tls listener")
	}

	return func() { go server.Serve(l) }, nil
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
				_ = localLn.HTTPServer.Shutdown(shutdownKill)
			}
		}()
	}
	serverWg.Wait()

	var retErr *multierror.Error
	if !w.conf.RawConfig.DevController {
		for _, ln := range w.conf.Listeners {
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
	}
	return retErr.ErrorOrNil()
}
