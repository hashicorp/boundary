// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyStateHelpers(t *testing.T) {
	old := ProxyState
	ProxyState = proxyState{}
	t.Cleanup(func() {
		ProxyState = old
	})

	t.Run("proxyConnFnCounter", func(t *testing.T) {
		assert.EqualValues(t, 0, ProxyState.CurrentProxiedConnections())
		proxyConnFnCounter(func(context.Context) {
			assert.EqualValues(t, 1, ProxyState.CurrentProxiedConnections())
		})(context.Background())
		assert.EqualValues(t, 0, ProxyState.CurrentProxiedConnections())
	})

	t.Run("ProxyHandlerCounter", func(t *testing.T) {
		assert.EqualValues(t, 0, ProxyState.CurrentProxiedConnections())
		var handlerRan bool
		h := ProxyHandlerCounter(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			handlerRan = true
			assert.EqualValues(t, 1, ProxyState.CurrentProxiedConnections())
		}))
		assert.EqualValues(t, 0, ProxyState.CurrentProxiedConnections())
		req, err := http.NewRequest("GET", "test/path", nil)
		require.NoError(t, err)
		h.ServeHTTP(httptest.NewRecorder(), req)
		require.True(t, handlerRan)
	})
}
