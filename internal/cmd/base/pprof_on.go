// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build pprof
// +build pprof

package base

import (
	"context"
	"errors"
	"net/http"

	"github.com/hashicorp/boundary/internal/event"

	_ "net/http/pprof"
)

func StartPprof(ctx context.Context) {
	const op = "base.StartPprof"
	go func() {
		const addr = "localhost:6060"
		event.WriteSysEvent(ctx, op, "starting pprof HTTP server", "addr", addr)
		if err := http.ListenAndServe(addr, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
			event.WriteSysEvent(ctx, op, "failed to serve pprof HTTP server", "error", err.Error())
		}
	}()
}
