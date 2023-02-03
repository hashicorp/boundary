// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !memprofiler
// +build !memprofiler

package base

import "context"

func StartMemProfiler(_ context.Context) {
}
