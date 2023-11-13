// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"net/http"
)

// new404Func creates a handler that returns a custom 404 error message.
func new404Func(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeError(w, "Not found", http.StatusNotFound)
	}
}
