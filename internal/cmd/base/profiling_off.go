// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !memprofiler
// +build !memprofiler

package base

import "context"

func StartMemProfiler(_ context.Context) {
}
