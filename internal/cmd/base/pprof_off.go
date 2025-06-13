// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !pprof
// +build !pprof

package base

import (
	"context"
)

func StartPprof(_ context.Context) {
}
