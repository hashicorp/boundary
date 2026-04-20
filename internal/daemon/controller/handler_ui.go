// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build ui

package controller

import (
	"bytes"
	"context"
	"net/http"
	"strings"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/ui"
)

func init() {
	handleUi = handleUiWithAssets
}

// serveMetadata provides controller metadata to the UI for licensed versions of Boundary.
var serveMetadata = func(ctx context.Context, w http.ResponseWriter) {}

// serveGrantSchema provides the grant schema to the UI for autocomplete and linting support.
var serveGrantSchema = func(ctx context.Context, w http.ResponseWriter) {
	const op = "controller.serveGrantSchema"
	data, err := perms.BuildGrantSchemaJSON(ctx)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		event.WriteError(ctx, op, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

const cspPlaceholder = "__BOUNDARY_CSP_NONCE__"

// cspWriter wraps an http.ResponseWriter to replace the CSP nonce placeholder
// in index.html with the actual nonce value.
type cspWriter struct {
	http.ResponseWriter
	nonce string
	done  bool
}

// WriteHeader removes the stale Content-Length since the body replacement
// changes the size.
func (w *cspWriter) WriteHeader(statusCode int) {
	//We need to force recalculation to avoid content length mismatch
	w.ResponseWriter.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *cspWriter) Write(b []byte) (int, error) {
	if !w.done {
		w.done = true
		b = bytes.Replace(b, []byte(cspPlaceholder), []byte(w.nonce), 1)
	}
	return w.ResponseWriter.Write(b)
}

func handleUiWithAssets(c *Controller) http.Handler {
	var nextHandler http.Handler
	if c.conf.RawConfig.DevUiPassthroughDir != "" {
		nextHandler = devUiPassthroughHandler(c.conf.RawConfig.DevUiPassthroughDir)
	} else {
		nextHandler = ui.Handler()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			//Lets remove nonce in case we return here
			w.Header().Del("X-Boundary-Csp-Nonce")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		dotIndex := strings.LastIndex(r.URL.Path, ".")
		switch dotIndex {
		case -1:
			// For all paths without an extension serve /index.html
			r.URL.Path = "/"

		default:
			switch r.URL.Path {
			case "/", "/favicon.png", "/assets/styles.css":
			case "/metadata.json":
				serveMetadata(c.baseContext, w)
				return
			case "/grants-schema.json":
				serveGrantSchema(c.baseContext, w)
				return
			default:
				for i := dotIndex + 1; i < len(r.URL.Path); i++ {
					intVal := r.URL.Path[i]
					// Current guidance from FE is if it's only alphanum after
					// the last dot, treat it as an extension
					if intVal < '0' ||
						(intVal > '9' && intVal < 'A') ||
						(intVal > 'Z' && intVal < 'a') ||
						intVal > 'z' {
						// Not an extension. Serve the contents of index.html
						r.URL.Path = "/"
					}
				}
			}
		}

		// For document requests, replace the CSP placeholder inside <head>.
		if r.URL.Path == "/" {
			if nonce := w.Header().Get("X-Boundary-Csp-Nonce"); nonce != "" {
				// Remove nonce once we have injected it in the Write() call
				w.Header().Del("X-Boundary-Csp-Nonce")
				nextHandler.ServeHTTP(&cspWriter{ResponseWriter: w, nonce: nonce}, r)
				return
			}
		}

		// Strip internal nonce header for non document requests
		w.Header().Del("X-Boundary-Csp-Nonce")
		nextHandler.ServeHTTP(w, r)
	})
}
