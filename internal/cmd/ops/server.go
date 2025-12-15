// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package ops encapsulates the lifecycle of Boundary's ops-purpose listeners
// and servers: Creating, setting them up, starting and shutdown.
package ops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/mitchellh/cli"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server is a collection of all state required to serve
// multiple ops endpoints through a single object.
type Server struct {
	bundles    []*opsBundle
	controller *controller.Controller
}

type opsBundle struct {
	ln      *base.ServerListener
	h       http.Handler
	startFn []func()
}

// NewServer iterates through all the listeners and sets up HTTP Servers for each, along with individual handlers.
// If Controller is set-up, NewServer will set-up a health endpoint for it.
func NewServer(ctx context.Context, l hclog.Logger, c *controller.Controller, w *worker.Worker, listeners ...*base.ServerListener) (*Server, error) {
	const op = "ops.NewServer()"
	if l == nil {
		return nil, fmt.Errorf("%s: missing logger", op)
	}

	bundles := make([]*opsBundle, 0, len(listeners))
	for _, ln := range listeners {
		if ln == nil || ln.Config == nil {
			continue
		}
		if ln.Config.Purpose[0] != "ops" {
			continue
		}
		if ln.OpsListener == nil {
			return nil, fmt.Errorf("%s: missing ops listener", op)
		}

		h, err := createOpsHandler(ctx, ln.Config, c, w)
		if err != nil {
			return nil, err
		}

		b := &opsBundle{ln: ln, h: h}
		b.ln.HTTPServer = createHttpServer(l, b.h, b.ln.Config)

		b.startFn = []func(){func() { go b.ln.HTTPServer.Serve(b.ln.OpsListener) }}

		bundles = append(bundles, b)
	}

	return &Server{bundles, c}, nil
}

// Starts all goroutines that were set-up in NewServer.
// These goroutines start the HTTP Servers on the appropriate
// listeners (as defined by the bundle).
func (s *Server) Start() {
	for _, b := range s.bundles {
		for _, f := range b.startFn {
			f()
		}
	}
}

// Shutdown attempts to cleanly shutdown all running ops listeners and HTTP servers.
func (s *Server) Shutdown() error {
	const op = "ops.(Server).Shutdown"

	var closeErrors error
	for _, b := range s.bundles {
		if b == nil || b.ln == nil || b.ln.Config == nil || b.ln.OpsListener == nil || b.ln.HTTPServer == nil {
			return fmt.Errorf("%s: missing bundle, listener or its fields", op)
		}

		ctx, cancel := context.WithTimeout(context.Background(), b.ln.Config.MaxRequestDuration)
		defer cancel()

		err := b.ln.HTTPServer.Shutdown(ctx)
		if err != nil {
			errors.Join(closeErrors, fmt.Errorf("%s: failed to shutdown http server: %w", op, err))
		}

		err = b.ln.OpsListener.Close()
		err = listenerCloseErrorCheck(b.ln.Config.Type, err)
		if err != nil {
			errors.Join(closeErrors, fmt.Errorf("%s: failed to close listener mux: %w", op, err))
		}
	}

	return closeErrors
}

// WaitIfHealthExists waits for a configurable period of time `d` if the health endpoint has been
// configured (i.e the Controller exists and ops listeners have been set-up)
func (s *Server) WaitIfHealthExists(d time.Duration, ui cli.Ui) {
	if s.controller == nil || s.controller.HealthService == nil {
		return
	}
	if len(s.bundles) == 0 {
		return
	}

	// If we have ops listeners and the health endpoint is up,
	// we wait for a configurable amount of time before shutting down.
	// This is to give time for health to report unhealthy and for external
	// systems to pick up on that.
	ui.Output(fmt.Sprintf("==> Health is enabled, waiting %s before shutdown", d.String()))
	s.controller.HealthService.StartServiceUnavailableReplies()
	<-time.After(d)
}

func createOpsHandler(ctx context.Context, lncfg *listenerutil.ListenerConfig, c *controller.Controller, w *worker.Worker) (http.Handler, error) {
	mux := http.NewServeMux()
	var h http.Handler
	var err error
	switch {
	case c != nil && c.HealthService != nil:
		h, err = c.GetHealthHandler(lncfg)
		if err != nil {
			return nil, err
		}
		if w != nil {
			c.HealthService.SetWorkerProcessInformationFunc(w.HealthInformation)
		}
	case w != nil:
		h, err = w.GetHealthHandler()
		if err != nil {
			return nil, err
		}
	}
	if h != nil {
		// Shouldn't happen since this function should only be called when
		// either a controller or worker is starting up, but just to be safe.
		mux.Handle("/health", h)
	}
	mux.Handle("/metrics", promhttp.Handler())
	return cleanhttp.PrintablePathCheckHandler(mux, nil), nil
}

func createHttpServer(l hclog.Logger, h http.Handler, lncfg *listenerutil.ListenerConfig) *http.Server {
	s := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ErrorLog:          l.StandardLogger(nil),
	}

	if lncfg.HTTPReadHeaderTimeout > 0 {
		s.ReadHeaderTimeout = lncfg.HTTPReadHeaderTimeout
	}
	if lncfg.HTTPReadTimeout > 0 {
		s.ReadTimeout = lncfg.HTTPReadTimeout
	}
	if lncfg.HTTPWriteTimeout > 0 {
		s.WriteTimeout = lncfg.HTTPWriteTimeout
	}
	if lncfg.HTTPIdleTimeout > 0 {
		s.IdleTimeout = lncfg.HTTPIdleTimeout
	}

	return s
}

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
