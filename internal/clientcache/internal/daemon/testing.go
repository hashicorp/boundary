// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

type TestServer struct {
	*CacheServer
	dotDir string
	cmd    Commander
}

// NewTestServer creates a test cache server using reasonable defaults for
// tests.  Supports the option WithDebugFlag to enable debug output for sql
func NewTestServer(t *testing.T, cmd Commander, opt ...Option) *TestServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dotDir := t.TempDir()

	cfg := &Config{
		ContextCancel:          cancel,
		RefreshInterval:        DefaultRefreshInterval,
		RecheckSupportInterval: DefaultRecheckSupportInterval,
		LogWriter:              io.Discard,
		DotDirectory:           dotDir,
		// we need to provide this, otherwise it will open a store in the user's
		// home dir. See db.Open(...)
		DatabaseUrl: dotDir + "cache.db?_pragma=foreign_keys(1)",
	}

	s, err := New(ctx, cfg)
	require.NoError(t, err)
	return &TestServer{
		CacheServer: s,
		dotDir:      dotDir,
		cmd:         cmd,
	}
}

// BaseDotDir returns the base directory in which the daemon socket is
// created.
func (s *TestServer) BaseDotDir() string {
	return s.dotDir
}

// Serve runs the cache server. This is a blocking call and returns when the
// server is shutdown or stops for any other reason.
func (s *TestServer) Serve(t *testing.T, opt ...Option) error {
	t.Helper()
	ctx := context.Background()

	t.Cleanup(func() {
		s.Shutdown(ctx)
	})
	return s.CacheServer.Serve(ctx, s.cmd, opt...)
}

func (s *TestServer) AddKeyringToken(t *testing.T, address, keyring, tokenName, tokenId string, atReadFn cache.BoundaryTokenReaderFn) {
	t.Helper()
	ctx := context.Background()
	r, err := cache.NewRepository(ctx, s.CacheServer.store.Load(), &sync.Map{}, s.cmd.ReadTokenFromKeyring, atReadFn)
	require.NoError(t, err)

	require.NoError(t, r.AddKeyringToken(ctx, address, cache.KeyringToken{
		KeyringType: keyring,
		TokenName:   tokenName,
		AuthTokenId: tokenId,
	}))
}

// AddResources adds targets, sessions, and aliases to the cache for the
// provided address, token name, and keyring type. They token info must already
// be known to the server.
func (s *TestServer) AddResources(t *testing.T, p *authtokens.AuthToken, alts []*aliases.Alias, tars []*targets.Target, sess []*sessions.Session, atReadFn cache.BoundaryTokenReaderFn) {
	t.Helper()
	ctx := context.Background()
	r, err := cache.NewRepository(ctx, s.CacheServer.store.Load(), &sync.Map{}, s.cmd.ReadTokenFromKeyring, atReadFn)
	require.NoError(t, err)

	altFn := func(ctx context.Context, _ string, tok, _ string, _ cache.RefreshTokenValue, inPage *aliases.AliasListResult, opt ...cache.Option) (*aliases.AliasListResult, cache.RefreshTokenValue, error) {
		if tok != p.Token {
			return nil, "", nil
		}
		return &aliases.AliasListResult{
			Items: alts,
		}, "addedaliases", nil
	}
	tarFn := func(ctx context.Context, _ string, tok string, _ cache.RefreshTokenValue, inPage *targets.TargetListResult, opt ...cache.Option) (*targets.TargetListResult, cache.RefreshTokenValue, error) {
		if tok != p.Token {
			return nil, "", nil
		}
		return &targets.TargetListResult{
			Items: tars,
		}, "addedtargets", nil
	}
	sessFn := func(ctx context.Context, _, tok string, _ cache.RefreshTokenValue, inPage *sessions.SessionListResult, opt ...cache.Option) (*sessions.SessionListResult, cache.RefreshTokenValue, error) {
		if tok != p.Token {
			return nil, "", nil
		}
		return &sessions.SessionListResult{
			Items: sess,
		}, "addedsessions", nil
	}
	rs, err := cache.NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
	require.NoError(t, err)
	require.NoError(t, rs.Refresh(ctx, cache.WithAliasRetrievalFunc(altFn), cache.WithTargetRetrievalFunc(tarFn), cache.WithSessionRetrievalFunc(sessFn)))
}

// AddUnsupportedCachingData provides data in a way that simulates it coming from
// a boundary instance that does not support refresh tokens. Since refresh tokens
// are required for caching, this has the effect of the data not being cached and
// the user being identified as not supported in the cache.
func (s *TestServer) AddUnsupportedCachingData(t *testing.T, p *authtokens.AuthToken, atReadFn cache.BoundaryTokenReaderFn) {
	t.Helper()
	ctx := context.Background()
	r, err := cache.NewRepository(ctx, s.CacheServer.store.Load(), &sync.Map{}, s.cmd.ReadTokenFromKeyring, atReadFn)
	require.NoError(t, err)

	tarFn := func(ctx context.Context, _, tok string, _ cache.RefreshTokenValue, inPage *targets.TargetListResult, opt ...cache.Option) (*targets.TargetListResult, cache.RefreshTokenValue, error) {
		if tok != p.Token {
			return &targets.TargetListResult{}, "", nil
		}
		return &targets.TargetListResult{
			Items: []*targets.Target{
				{Id: "ttcp_unsupported", Name: "unsupported", Description: "not supported"},
			},
		}, "", cache.ErrRefreshNotSupported
	}
	sessFn := func(ctx context.Context, _, tok string, _ cache.RefreshTokenValue, inPage *sessions.SessionListResult, opt ...cache.Option) (*sessions.SessionListResult, cache.RefreshTokenValue, error) {
		if tok != p.Token {
			return &sessions.SessionListResult{}, "", nil
		}
		return &sessions.SessionListResult{
			Items: []*sessions.Session{
				{Id: "s_unsupported"},
			},
		}, "", cache.ErrRefreshNotSupported
	}
	rs, err := cache.NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
	require.NoError(t, err)
	err = rs.Refresh(ctx, cache.WithTargetRetrievalFunc(tarFn), cache.WithSessionRetrievalFunc(sessFn))
	require.ErrorContains(t, err, "not supported for this controller")
}
