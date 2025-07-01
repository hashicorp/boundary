// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !go1.20
// +build !go1.20

package listenerutil

import (
	"bufio"
	"net"
	"net/http"
)

type ResponseWriter struct {
	wrapped http.ResponseWriter
	// headers contain a map of response code to header map such that
	// headers[status][header name] = header value
	// this map also contains values for hundred-level values in the format 1: "1xx", 2: "2xx", etc
	// defaults are set to 0
	headers       map[int]http.Header
	headerWritten bool
}

// Implement http.Flusher if available.
func (w *ResponseWriter) Flush() {
	f, ok := w.wrapped.(http.Flusher)
	if ok {
		f.Flush()
	}
}

// Implement http.Hijacker if available.
func (w *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.wrapped.(http.Hijacker)
	if ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// WrapCustomHeadersHandler wraps the handler to pass a custom ResponseWriter struct to all
// later wrappers and handlers to assign custom headers by status code. This wrapper must
// be the outermost wrapper to function correctly.
func WrapCustomHeadersHandler(h http.Handler, config *ListenerConfig, isUiRequest uiRequestFunc) http.Handler {
	uiHeaders := config.CustomUiResponseHeaders
	apiHeaders := config.CustomApiResponseHeaders

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// this function is extremely generic as all we want to do is wrap the http.ResponseWriter
		// in our own ResponseWriter above, which will then perform all the logic we actually want

		var headers map[int]http.Header

		if isUiRequest(req) {
			headers = uiHeaders
		} else {
			headers = apiHeaders
		}

		wrappedWriter := &ResponseWriter{
			wrapped: w,
			headers: headers,
		}
		h.ServeHTTP(wrappedWriter, req)

		if !wrappedWriter.headerWritten {
			wrappedWriter.WriteHeader(http.StatusOK)
		}
	})
}
