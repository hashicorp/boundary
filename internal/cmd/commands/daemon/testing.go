// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	stdErrors "errors"
	"io"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/stretchr/testify/require"
)

type TestServer struct {
	*cacheServer
	socketDir string
	cmd       Commander
}

// NewTestServer creates a test cache server using reasonable defaults for
// tests.  Supports the option WithDebugFlag to enable debug output for sql
func NewTestServer(t *testing.T, cmd Commander, opt ...Option) *TestServer {
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
func (s *TestServer) Serve(t *testing.T, opt ...Option) error {
	t.Helper()
	ctx := context.Background()

	l, err := listener(ctx, s.socketDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		s.shutdown(ctx)
	})
	return s.cacheServer.serve(ctx, s.cmd, l, opt...)
}

// AddResources adds targets to the cache for the provided address, token name,
// and keyring type. They token info must already be known to the server.
func (s *TestServer) AddResources(t *testing.T, p *authtokens.AuthToken, tars []*targets.Target, sess []*sessions.Session) {
	t.Helper()
	ctx := context.Background()
	r, err := cache.NewRepository(ctx, s.cacheServer.store, &sync.Map{}, s.cmd.ReadTokenFromKeyring, unimplementedAuthTokenReader)
	require.NoError(t, err)

	tarFn := func(ctx context.Context, _, tok string) ([]*targets.Target, error) {
		if tok != p.Token {
			return nil, nil
		}
		return tars, nil
	}
	sessFn := func(ctx context.Context, _, tok string) ([]*sessions.Session, error) {
		if tok != p.Token {
			return nil, nil
		}
		return sess, nil
	}
	require.NoError(t, r.Refresh(ctx, cache.WithTargetRetrievalFunc(tarFn), cache.WithSessionRetrievalFunc(sessFn)))
}

// unimplementedAuthTokenReader is an unimplemented function for reading auth
// tokens from a provided boundary address.
func unimplementedAuthTokenReader(ctx context.Context, addr string, authToken string) (*authtokens.AuthToken, error) {
	return nil, stdErrors.New("unimplemented")
}
