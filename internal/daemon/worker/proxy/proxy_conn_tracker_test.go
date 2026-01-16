// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyStateHelpers(t *testing.T) {
	old := ProxyState
	ProxyState = proxyState{proxyCount: new(atomic.Int64)}
	t.Cleanup(func() {
		ProxyState = old
	})

	t.Run("proxyConnFnCounter", func(t *testing.T) {
		assert.EqualValues(t, 0, ProxyState.CurrentProxiedConnections())
		proxyConnFnCounter(func() {
			assert.EqualValues(t, 1, ProxyState.CurrentProxiedConnections())
		})()
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
