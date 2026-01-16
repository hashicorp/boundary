// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

// MigrationCheckError is an error returned when a migration hook check function
// reports an error.
type MigrationCheckError struct {
	Version           int
	Edition           string
	Problems          migration.Problems
	RepairDescription string
}

func (e MigrationCheckError) Error() string {
	return fmt.Sprintf("check failed for %s:%d", e.Edition, e.Version)
}
