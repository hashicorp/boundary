// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build !pprof
// +build !pprof

package base

import (
	"context"
)

func StartPprof(_ context.Context) {
}
