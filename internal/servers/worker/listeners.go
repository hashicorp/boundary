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

func (w *Worker) stopServersAndListeners() error {
	var closeErrors *multierror.Error
	err := w.stopHttpServersAndListeners()
	if err != nil {
		closeErrors = multierror.Append(closeErrors, err)
	}

	err = w.stopAnyListeners()
	if err != nil {
		closeErrors = multierror.Append(closeErrors, err)
	}

	return closeErrors.ErrorOrNil()
}

func (w *Worker) stopHttpServersAndListeners() error {
	var closeErrors *multierror.Error
	for i := range w.listeners {
		ln := w.listeners[i]
		if ln.HTTPServer == nil {
			continue
		}

		ctx, cancel := context.WithTimeout(w.baseContext, ln.Config.MaxRequestDuration)
		ln.HTTPServer.Shutdown(ctx)
		cancel()

		err := ln.Mux.Close()
		err = listenerCloseErrorCheck(ln.Config.Type, err)
		if err != nil {
			multierror.Append(closeErrors, err)
		}
	}

	return closeErrors.ErrorOrNil()
}

// stopAnyListeners does a final once over the known
// listeners to make sure we didn't miss any;
// expected to run at the end of stopServersAndListeners.
func (w *Worker) stopAnyListeners() error {
	var closeErrors *multierror.Error
	for _, ln := range w.listeners {
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
