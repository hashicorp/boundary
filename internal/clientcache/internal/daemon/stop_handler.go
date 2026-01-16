// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"net/http"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// newStopHandlerFunc creates a handler that cancels the server context.
// This is only expected to be used on windows currently since it cannot use
// POSIX signals to perform a graceful shutdown.
func newStopHandlerFunc(ctx context.Context, cancelFn context.CancelFunc) (http.HandlerFunc, error) {
	const op = "daemon.newSearchTargetsHandlerFunc"
	switch {
	case util.IsNil(cancelFn):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "server cancelFn is missing")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, "only method POST allowed", http.StatusMethodNotAllowed)
		}

		w.WriteHeader(http.StatusNoContent)
		cancelFn()
	}, nil
}
