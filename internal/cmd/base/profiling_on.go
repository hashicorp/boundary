// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build memprofiler
// +build memprofiler

package base

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/hashicorp/boundary/internal/observability/event"
)

func StartMemProfiler(ctx context.Context) {
	const op = "base.StartMemProfiler"
	profileDir := filepath.Join(os.TempDir(), "boundaryprof")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("could not create profile directory"))
		return
	}

	go func() {
		for {
			filename := filepath.Join(profileDir, time.Now().UTC().Format("20060102_150405")) + ".pprof"
			f, err := os.Create(filename)
			if err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("could not create memory profile"))
			}
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("could not write memory profile"))
			}
			f.Close()
			event.WriteSysEvent(ctx, op, "wrote memory profile", "filename", filename)
			time.Sleep(5 * time.Minute)
		}
	}()
}
