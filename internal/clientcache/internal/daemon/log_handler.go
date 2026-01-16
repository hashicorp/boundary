// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/hashicorp/boundary/internal/event"
)

// LogRequest is the request body to this handler.
type LogRequest struct {
	// Message is a required field for all requests
	Message string `json:"message,omitempty"`
	Op      string `json:"op,omitempty"`
}

// newLogHandlerFunc creates a handler that logs a system event using the
// daemon's eventer.
func newLogHandlerFunc(ctx context.Context) (http.HandlerFunc, error) {
	const op = "daemon.newLogHandlerFunc"

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, "only method POST allowed", http.StatusMethodNotAllowed)
		}

		var perReq LogRequest
		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, "unable to read request body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(data, &perReq); err != nil {
			// If, for whatever reason, we can't parse the request body as json
			// can still log that the request to log was received and print out
			// the body of the request.
			event.WriteError(ctx, op, err, event.WithInfo("body", string(data)))
			writeError(w, "unable to parse request body", http.StatusBadRequest)
			return
		}

		event.WriteSysEvent(ctx, op, perReq.Message, "requester_op", perReq.Op)
		w.WriteHeader(http.StatusNoContent)
	}, nil
}
