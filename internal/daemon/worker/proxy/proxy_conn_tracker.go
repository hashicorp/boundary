// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"net/http"
	"sync/atomic"
)

// ProxyState contains the current state of proxies in this process.
var ProxyState proxyState

type proxyState struct {
	proxyCount atomic.Int64
}

// CurrentProxiedConnections returns the current number of ongoing proxied
// connections which are currently running the Handler's ProxyConnFn.
func (p *proxyState) CurrentProxiedConnections() int64 {
	return p.proxyCount.Load()
}

// HttpHandlerCounter records how many requests are currently running in the
// wrapped Handler. This should be used for handlers that serve proxied traffic.
func ProxyHandlerCounter(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ProxyState.proxyCount.Add(1)
		defer ProxyState.proxyCount.Add(-1)
		h.ServeHTTP(rw, r)
	})
}

// proxyConnFnCounter wraps a ProxyState and keeps the proxyCount incremented
// while it runs.
func proxyConnFnCounter(fn ProxyConnFn) ProxyConnFn {
	return func(ctx context.Context) {
		ProxyState.proxyCount.Add(1)
		defer ProxyState.proxyCount.Add(-1)
		fn(ctx)
	}
}
