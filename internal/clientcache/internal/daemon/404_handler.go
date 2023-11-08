// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"net/http"
)

// newStopHandlerFunc creates a handler that cancels the server context.
// This is only expected to be used on windows currently since it cannot use
// POSIX signals to perform a graceful shutdown.
func new404Func(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeError(w, "Not found", http.StatusNotFound)
	}
}
