// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_New(t *testing.T) {
	ctx := context.Background()

	t.Run("nil addr", func(t *testing.T) {
		_, err := New(ctx, nil)
		assert.ErrorContains(t, err, "address is nil")
	})
	t.Run("schema not unix", func(t *testing.T) {
		u, err := url.Parse("http://127.0.0.1/v2/something")
		require.NoError(t, err)
		_, err = New(ctx, u)
		assert.ErrorContains(t, err, "address does not have a unix schema")
	})
	t.Run("schema not unix", func(t *testing.T) {
		u, err := url.Parse("unix://")
		require.NoError(t, err)
		_, err = New(ctx, u)
		assert.ErrorContains(t, err, "address path is empty")
	})
	t.Run("success", func(t *testing.T) {
		u, err := url.Parse("unix:///User/boundary/test.sock")
		require.NoError(t, err)
		c, err := New(ctx, u)
		assert.NoError(t, err)
		assert.NotNil(t, c)
	})
}

func TestClient(t *testing.T) {
	ctx := context.Background()
	testPath := "/v1/test_endpoint"

	tmpDir := t.TempDir()
	unixSocket := filepath.Join(tmpDir, "test.sock")
	l, err := net.Listen("unix", unixSocket)
	require.NoError(t, err)

	var assertRequest func(*http.Request)
	writeResp := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusNoContent)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(testPath, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { // Mock for the proxy handler.
		assertRequest(req)
		writeResp(rw)
	}))

	var serverShutdown sync.WaitGroup
	serverShutdown.Add(1)
	go func() {
		defer serverShutdown.Done()
		http.Serve(l, mux)
	}()

	u, err := url.Parse(fmt.Sprintf("unix://%s", unixSocket))
	require.NoError(t, err)
	c, err := New(ctx, u)
	require.NoError(t, err)

	t.Run("not found", func(t *testing.T) {
		r, err := c.Get(ctx, "/unknown/path", nil)
		assert.NoError(t, err)
		assert.NotNil(t, r)
		r.HttpResponse().Body.Close()
		assert.Equal(t, http.StatusNotFound, r.HttpResponse().StatusCode)
	})

	t.Run("empty response", func(t *testing.T) {
		assertRequest = func(r *http.Request) {
			assert.Equal(t, r.Method, http.MethodGet)
			assert.NotEmpty(t, r.Header.Get(daemon.VersionHeaderKey))
		}
		r, err := c.Get(ctx, testPath, nil)
		assert.NoError(t, err)
		apiErr, err := r.Decode(nil)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
	})

	t.Run("empty response", func(t *testing.T) {
		assertRequest = func(r *http.Request) {
			assert.Equal(t, r.Method, http.MethodGet)
			assert.NotEmpty(t, r.Header.Get(daemon.VersionHeaderKey))
		}
		r, err := c.Get(ctx, testPath, nil)
		assert.NoError(t, err)
		assert.NotNil(t, r)

		apiErr, err := r.Decode(nil)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.Empty(t, r.Body)
	})

	t.Run("empty json object", func(t *testing.T) {
		assertRequest = func(r *http.Request) {
			assert.Equal(t, r.Method, http.MethodGet)
			assert.NotEmpty(t, r.Header.Get(daemon.VersionHeaderKey))
		}
		writeResp = func(w http.ResponseWriter) {
			w.Write([]byte("{}"))
			w.WriteHeader(http.StatusOK)
		}
		r, err := c.Get(ctx, testPath, nil)
		assert.NoError(t, err)
		assert.NotNil(t, r)

		apiErr, err := r.Decode(nil)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.Equal(t, "{}", string(r.Body.Bytes()))
	})

	t.Run("query params", func(t *testing.T) {
		v := url.Values{}
		v.Add("foo", "bar")

		assertRequest = func(r *http.Request) {
			assert.Equal(t, r.Method, http.MethodGet)
			assert.Equal(t, v, r.URL.Query())
			assert.NotEmpty(t, r.Header.Get(daemon.VersionHeaderKey))
		}
		r, err := c.Get(ctx, testPath, &v)
		assert.NoError(t, err)
		apiErr, err := r.Decode(nil)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
	})

	t.Run("empty json object", func(t *testing.T) {
		assertRequest = func(r *http.Request) {
			assert.Equal(t, r.Method, http.MethodPost)
			assert.NotEmpty(t, r.Header.Get(daemon.VersionHeaderKey))
			b, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Equal(t, string(b), `{"foo":"bar"}`)
		}
		r, err := c.Post(ctx, testPath, map[string]interface{}{"foo": "bar"})
		assert.NoError(t, err)
		assert.NotNil(t, r)

		apiErr, err := r.Decode(nil)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
	})

	l.Close()
	serverShutdown.Wait()
}
