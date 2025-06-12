// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !pprof
// +build !pprof

package base

import (
	"context"
)

func StartPproff(_ context.Context) {
	go func() {
	}()

}
