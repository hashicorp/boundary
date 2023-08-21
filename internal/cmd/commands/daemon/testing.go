// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"io"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/stretchr/testify/require"
)

type TestServer struct {
	*cacheServer
	socketDir          string
	setupLoggingCalled bool
}

// NewTestServer creates a test cache server using reasonable defaults for
// tests.  Supports the option WithDebugFlag to enable debug output for sql
func NewTestServer(t *testing.T, opt ...Option) *TestServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	opts, err := getOpts(opt...)
	require.NoError(t, err)

	cfg := serverConfig{
		contextCancel:          cancel,
		refreshIntervalSeconds: DefaultRefreshIntervalSeconds,
		flagStoreDebug:         opts.withDebug,
	}

	s, err := newServer(ctx, cfg)
	require.NoError(t, err)
	return &TestServer{cacheServer: s, socketDir: t.TempDir()}
}

// BaseSocketDir returns the base directory in which the daemon socket is
// created.
func (s *TestServer) BaseSocketDir() string {
	return s.socketDir
}

// Serve runs the cache server. This is a blocking call and returns when the
// server is shutdown or stops for any other reason.
func (s *TestServer) Serve(t *testing.T, cmd commander) error {
	t.Helper()
	ctx := context.Background()

	l, err := listener(ctx, s.socketDir)
	require.NoError(t, err)

	if !s.setupLoggingCalled {
		// logging wasn't called so discard all output from the server.
		require.NoError(t, s.cacheServer.setupLogging(ctx, io.Discard))
	}

	t.Cleanup(func() {
		s.shutdown(ctx)
	})
	return s.cacheServer.serve(ctx, cmd, l)
}

// AddTargets adds targets to the cache for the provided Persona. The persona
// must be one already known to the server.
func (s *TestServer) AddTargets(t *testing.T, p *cache.Persona, tars []*targets.Target) {
	t.Helper()
	ctx := context.Background()
	r, err := cache.NewRepository(ctx, s.cacheServer.store)
	require.NoError(t, err)
	require.NoError(t, r.RefreshTargets(ctx, p, tars))
}

func (s *TestServer) setupLogging(ctx context.Context, w io.Writer) error {
	s.setupLoggingCalled = true
	return s.cacheServer.setupLogging(ctx, w)
}

func (s *TestServer) SetupLogging(ctx context.Context, w io.Writer) error {
	return s.setupLogging(ctx, w)
}
