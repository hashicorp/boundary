// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"net/http"
)

// new404Func creates a handler that returns a custom 404 error message.
func new404Func(_ context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeError(w, "Not found", http.StatusNotFound)
	}
}
