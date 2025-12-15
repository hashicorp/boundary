// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build !netbsd
// +build !netbsd

package main

import (
	minio "github.com/hashicorp/boundary-plugin-minio/plugin"
	hp "github.com/hashicorp/boundary/sdk/plugins"
)

func serve() error {
	return hp.ServePlugin(minio.NewMinioPlugin())
}
