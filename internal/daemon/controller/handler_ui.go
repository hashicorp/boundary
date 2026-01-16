// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build ui

package controller

import (
	"context"
	"net/http"
	"strings"

	"github.com/hashicorp/boundary/internal/ui"
)

func init() {
	handleUi = handleUiWithAssets
}

// serveMetadata provides controller metadata to the UI for licensed versions of Boundary.
var serveMetadata = func(ctx context.Context, w http.ResponseWriter) {}

func handleUiWithAssets(c *Controller) http.Handler {
	var nextHandler http.Handler
	if c.conf.RawConfig.DevUiPassthroughDir != "" {
		nextHandler = devUiPassthroughHandler(c.conf.RawConfig.DevUiPassthroughDir)
	} else {
		nextHandler = ui.Handler()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
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

		// Fall through to the next handler
		nextHandler.ServeHTTP(w, r)
	})
}
