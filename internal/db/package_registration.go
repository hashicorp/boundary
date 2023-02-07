// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package db

import (
	// import for init side-effects to include migrations
	_ "github.com/hashicorp/boundary/internal/db/schema/migrations/oss"
)
