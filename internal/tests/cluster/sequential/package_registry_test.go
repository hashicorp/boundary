// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package sequential

import (
	// Enable tcp target support.
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	_ "github.com/hashicorp/boundary/internal/target/tcp"
)
