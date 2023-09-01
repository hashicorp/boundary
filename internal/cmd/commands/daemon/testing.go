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
	socketDir string
	cmd       commander
}

// NewTestServer creates a test cache server using reasonable defaults for
// tests.  Supports the option WithDebugFlag to enable debug output for sql
func NewTestServer(t *testing.T, cmd commander, opt ...Option) *TestServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	opts, err := getOpts(opt...)
	require.NoError(t, err)

	cfg := &serverConfig{
		contextCancel:          cancel,
		refreshIntervalSeconds: DefaultRefreshIntervalSeconds,
		flagStoreDebug:         opts.withDebug,
		logWriter:              io.Discard,
	}

	s, err := newServer(ctx, cfg)
	require.NoError(t, err)
	return &TestServer{
		cacheServer: s,
		socketDir:   t.TempDir(),
		cmd:         cmd,
	}
}

// BaseSocketDir returns the base directory in which the daemon socket is
// created.
func (s *TestServer) BaseSocketDir() string {
	return s.socketDir
}

// Serve runs the cache server. This is a blocking call and returns when the
// server is shutdown or stops for any other reason.
func (s *TestServer) Serve(t *testing.T) error {
	t.Helper()
	ctx := context.Background()

	l, err := listener(ctx, s.socketDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		s.shutdown(ctx)
	})
	return s.cacheServer.serve(ctx, s.cmd, l)
}

// AddTargets adds targets to the cache for the provided address, token name, and keyring type.
// They token info must already be known to the server.
func (s *TestServer) AddTargets(t *testing.T, tarAddr string, tarToken string, tars []*targets.Target) {
	t.Helper()
	ctx := context.Background()
	r, err := cache.NewRepository(ctx, s.cacheServer.store, s.cmd.ReadTokenFromKeyring)
	require.NoError(t, err)

	tarFn := func(ctx context.Context, addr string, tok string) ([]*targets.Target, error) {
		if addr != tarAddr || tok != tarToken {
			return nil, nil
		}
		return tars, nil
	}
	require.NoError(t, r.Refresh(ctx, cache.WithTargetRetrievalFunc(tarFn)))
}
