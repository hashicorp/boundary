// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	// import for init side-effects to include migrations
	_ "github.com/hashicorp/boundary/internal/db/schema/migrations/oss"
)
