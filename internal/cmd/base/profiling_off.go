//go:build !memprofiler
// +build !memprofiler

package base

import "context"

func StartMemProfiler(_ context.Context) {
}
