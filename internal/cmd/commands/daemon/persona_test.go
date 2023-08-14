// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/daemon/cache"
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
	at string
}

func (r *testAtReader) ReadTokenFromKeyring(k, a string) *authtokens.AuthToken {
	return &authtokens.AuthToken{
		Id:           r.at,
		AuthMethodId: "test_auth_method",
		Token:        fmt.Sprintf("%s_%s", r.at, a),
	}
}

func TestPersona(t *testing.T) {
	ctx := context.Background()
	s, _, err := openStore(ctx, "", true)
	require.NoError(t, err)

	tr := &testRefresher{}
	ph, err := newPersonaHandlerFunc(ctx, s, &testAtReader{"at_1234567890"}, tr)
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
		pa := &personaToAdd{
			KeyringType:  "",
			TokenName:    "default",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_1234567890",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "KeyringType is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing token name", func(t *testing.T) {
		pa := &personaToAdd{
			KeyringType:  "akeyringtype",
			TokenName:    "",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_1234567890",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "TokenName is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing boundary address", func(t *testing.T) {
		pa := &personaToAdd{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "",
			AuthTokenId:  "at_1234567890",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "BoundaryAddr is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing auth token id", func(t *testing.T) {
		pa := &personaToAdd{
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
		pa := &personaToAdd{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_doesntmatch",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "id doesn't match")
		assert.False(t, tr.called)
	})

	t.Run("success", func(t *testing.T) {
		pa := &personaToAdd{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_1234567890",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.True(t, tr.called)

		repo, err := cache.NewRepository(ctx, s)
		require.NoError(t, err)

		p, err := repo.LookupPersona(ctx, pa.BoundaryAddr, pa.KeyringType, pa.TokenName)
		require.NoError(t, err)
		assert.NotNil(t, p)
		assert.LessOrEqual(t, p.LastAccessedTime, time.Now())

		p.LastAccessedTime = time.Time{}
		assert.Equal(t, &cache.Persona{
			BoundaryAddr: pa.BoundaryAddr,
			KeyringType:  pa.KeyringType,
			TokenName:    pa.TokenName,
			AuthTokenId:  "at_1234567890",
		}, p)
	})
	srv.Shutdown(ctx)
	wg.Wait()
}
