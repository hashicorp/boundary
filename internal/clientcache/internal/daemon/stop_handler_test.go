// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStopHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ph, err := newStopHandlerFunc(ctx, cancel)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/stop", ph)

	t.Run("get", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/stop", nil)
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Result().StatusCode)
	})

	t.Run("delete", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/v1/stop", nil)
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Result().StatusCode)
	})

	t.Run("success", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/stop", nil)
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Result().StatusCode)
		assert.Error(t, ctx.Err())
	})
}
