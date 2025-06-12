// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build pprof
// +build pprof

package base

import (
	"context"
	"log"

	"net/http"
	_ "net/http/pprof"
)

func StartPproff(_ context.Context) {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

}
