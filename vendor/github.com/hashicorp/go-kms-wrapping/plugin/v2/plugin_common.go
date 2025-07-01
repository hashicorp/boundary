// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//go:build !js

package plugin

import "syscall"

const sighup = syscall.SIGHUP
