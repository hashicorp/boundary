// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TesSearch(t *testing.T) {
	ctx := context.Background()
	s, _, err := openStore(ctx, "", true)
	require.NoError(t, err)

	sh, err := newSearchTargetsHandlerFunc(ctx, s)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/search", sh)

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
	})

	t.Run("missing boundary address", func(t *testing.T) {
		pa := &personaToAdd{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "BoundaryAddr is a required field but was empty")
	})

	t.Run("success", func(t *testing.T) {
		pa := &personaToAdd{
			KeyringType:  "akeyringtype",
			TokenName:    "default",
			BoundaryAddr: "http://127.0.0.1",
		}
		apiErr, err := addPersona(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)

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
