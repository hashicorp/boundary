// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	// Enable tcp target support.
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	_ "github.com/hashicorp/boundary/internal/target/tcp"
)
