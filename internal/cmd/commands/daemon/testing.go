// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

type TestServer struct {
	*cacheServer
	socketDir string
}

// NewTestServer creates a test cache server using reasonable defaults for
// tests.  Supports the option WithDebugFlag to enable debug output for sql
func NewTestServer(t *testing.T, opt ...Option) *TestServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	buf := bytes.NewBuffer(nil)

	ui := &base.BoundaryUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader: bufio.NewReader(buf),
				Writer: buf,
			},
		},
		Format: "table",
	}

	opts, err := getOpts(opt...)
	require.NoError(t, err)

	cfg := serverConfig{
		contextCancel:          cancel,
		refreshIntervalSeconds: DefaultRefreshIntervalSeconds,
		ui:                     ui,
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

	t.Cleanup(func() {
		s.shutdown()
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

// Shutdown shuts down the underlying cache server
func (s *TestServer) Shutdown() {
	s.shutdown()
}
