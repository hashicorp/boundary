// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build netbsd
// +build netbsd

package main

import (
	"fmt"
)

func serve() error {
	return fmt.Errorf("Minio is not supported in netbsd")
}
