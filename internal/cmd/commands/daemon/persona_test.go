// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testRefresher struct {
	called bool
}

func (r *testRefresher) refresh() {
	r.called = true
}

type testAtReader struct {
	atId string
}

func (r *testAtReader) ReadTokenFromKeyring(k, a string) *authtokens.AuthToken {
	return &authtokens.AuthToken{
		Id:           r.atId,
		AuthMethodId: "test_auth_method",
		Token:        fmt.Sprintf("%s_%s", r.atId, a),
		UserId:       r.atId,
	}
}

func TestPersona_ringNone(t *testing.T) {
	cmd := StartCommand{Command: base.NewCommand(nil)}
	ctx := context.Background()
	s, _, err := openStore(ctx, "", false)
	require.NoError(t, err)

	repo, err := cache.NewRepository(ctx, s, cmd.ReadTokenFromKeyring, defaultAuthTokenRead(cmd))
	require.NoError(t, err)

	tr := &testRefresher{}
	ph, err := newPersonaHandlerFunc(ctx, repo, tr)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/personas", ph)

	tmpdir := t.TempDir()
	l, err := listener(ctx, tmpdir)
	require.NoError(t, err)
	srv := &http.Server{
		Handler: mux,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.ErrorIs(t, srv.Serve(l), http.ErrServerClosed)
	}()

	tc := controller.NewTestController(t, nil)
	t.Cleanup(func() {
		tc.Shutdown()
	})

	t.Run("none keyring mismatched token name", func(t *testing.T) {
		at := tc.Token()
		pa := &upsertPersonaRequest{
			KeyringType:  "none",
			TokenName:    "tokename",
			BoundaryAddr: tc.ApiAddrs()[0],
			AuthTokenId:  at.Id,
			AuthToken:    at.Token,
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		require.NotNil(t, apiErr)
		assert.False(t, tr.called)
		assert.Contains(t, apiErr.Message, "TokenName must match the AuthTokenId")
	})

	t.Run("success with none keyring", func(t *testing.T) {
		at := tc.Token()
		pa := &upsertPersonaRequest{
			KeyringType:  "none",
			TokenName:    at.Id,
			BoundaryAddr: tc.ApiAddrs()[0],
			AuthTokenId:  at.Id,
			AuthToken:    at.Token,
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.True(t, tr.called)

		p, err := repo.LookupPersona(ctx, pa.TokenName, pa.KeyringType)
		require.NoError(t, err)
		assert.NotNil(t, p)
		assert.Equal(t, at.Id, p.AuthTokenId)
	})
}

func TestPersona(t *testing.T) {
	ctx := context.Background()
	s, _, err := openStore(ctx, "", false)
	require.NoError(t, err)

	atReader := &testAtReader{"at_1234567890"}
	repo, err := cache.NewRepository(ctx, s, atReader.ReadTokenFromKeyring, unimplementedAuthTokenReader)
	require.NoError(t, err)

	tr := &testRefresher{}
	ph, err := newPersonaHandlerFunc(ctx, repo, tr)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/personas", ph)

	tmpdir := t.TempDir()
	l, err := listener(ctx, tmpdir)
	require.NoError(t, err)
	srv := &http.Server{
		Handler: mux,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.ErrorIs(t, srv.Serve(l), http.ErrServerClosed)
	}()

	t.Run("missing keyring", func(t *testing.T) {
		pa := &upsertPersonaRequest{
			KeyringType:  "",
			TokenName:    "default",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  atReader.atId,
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "KeyringType is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing token name", func(t *testing.T) {
		pa := &upsertPersonaRequest{
			KeyringType:  "akeyringtype",
			TokenName:    "",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  atReader.atId,
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "TokenName is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing boundary address", func(t *testing.T) {
		pa := &upsertPersonaRequest{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "",
			AuthTokenId:  atReader.atId,
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "BoundaryAddr is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing auth token id", func(t *testing.T) {
		pa := &upsertPersonaRequest{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "AuthTokenId is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("mismatched auth token id", func(t *testing.T) {
		pa := &upsertPersonaRequest{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_doesntmatch",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "Failed to add a persona")
		assert.False(t, tr.called)
	})

	t.Run("success", func(t *testing.T) {
		pa := &upsertPersonaRequest{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  atReader.atId,
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.True(t, tr.called)

		p, err := repo.LookupPersona(ctx, pa.TokenName, pa.KeyringType)
		require.NoError(t, err)
		assert.NotNil(t, p)
		assert.Equal(t, atReader.atId, p.AuthTokenId)
	})
	srv.Shutdown(ctx)
	wg.Wait()
}
