// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package log

import "time"

// Entry represents a log entry generated during migrations.
type Entry struct {
	Id               int
	MigrationEdition string
	MigrationVersion int
	CreateTime       time.Time
	Entry            string
}
