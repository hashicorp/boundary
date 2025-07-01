// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package listenerutil

import (
	"net/http"
)

type uiRequestFunc func(*http.Request) bool

func (w *ResponseWriter) WriteHeader(statusCode int) {
	w.headerWritten = true
	w.setCustomResponseHeaders(statusCode)
	w.wrapped.WriteHeader(statusCode)
}

func (w *ResponseWriter) Header() http.Header {
	return w.wrapped.Header()
}

func (w *ResponseWriter) Write(data []byte) (int, error) {
	// The default behavior of http.ResponseWriter.Write is such that if WriteHeader has not
	// yet been called, it calls it with the below line. We will copy that logic so that our
	// WriteHeader function is called rather than http.ResponseWriter.WriteHeader
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	return w.wrapped.Write(data)
}

// Provide Unwrap for users of http.ResponseController
func (w *ResponseWriter) Unwrap() http.ResponseWriter {
	return w.wrapped
}

// Implement http.Pusher if available.
func (w *ResponseWriter) Push(target string, opts *http.PushOptions) error {
	p, ok := w.wrapped.(http.Pusher)
	if ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *ResponseWriter) setCustomResponseHeaders(statusCode int) {
	sch := w.headers
	if sch == nil {
		return
	}

	// Check the validity of the status code
	if statusCode >= 600 || statusCode < 100 {
		return
	}

	// Setter function to set headers
	setter := func(headerMap map[string][]string) {
		for header, values := range headerMap {
			w.Header().Del(header)
			for _, value := range values {
				w.Header().Add(header, value)
			}
		}
	}

	// Setting the default headers first
	if val, ok := sch[0]; ok {
		setter(val)
	}

	// Then setting the generic hundred-level headers
	// Note: integer division always rounds down, so 499/100 = 4
	if val, ok := sch[statusCode/100]; ok {
		setter(val)
	}

	// Finally setting the status-specific headers
	if val, ok := sch[statusCode]; ok {
		setter(val)
	}
}
