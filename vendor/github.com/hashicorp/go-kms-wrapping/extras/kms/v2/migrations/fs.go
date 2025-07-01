// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package migrations

import "embed"

// Version defines the current migrations version required by the module
const Version = "v0.0.2"

// PostgresFS contains the sql for creating the postgres tables
//
//go:embed postgres
var PostgresFS embed.FS

// SqliteFS contains the sql for creating the sqlite tables
//
//go:embed sqlite
var SqliteFS embed.FS
