// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !memprofiler
// +build !memprofiler

package base

import "context"

func StartMemProfiler(_ context.Context) {
}
