// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/boundary/version"
	"github.com/stretchr/testify/assert"
)

func TestVersionEnforcement(t *testing.T) {
	var called bool
	calledHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	h := versionEnforcement(calledHandler)

	t.Run("no version provided", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("", "/test", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
	})

	t.Run("bad version provided", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("", "/test", nil)
		req.Header.Set(VersionHeaderKey, "badversion")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		assert.False(t, called)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("correct version provided", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("", "/test", nil)
		req.Header.Set(VersionHeaderKey, version.Get().VersionNumber())
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
	})
}
