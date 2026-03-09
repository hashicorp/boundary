// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package parallel

import (
	// Enable tcp target support.
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	_ "github.com/hashicorp/boundary/internal/target/tcp"
)
