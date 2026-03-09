// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
)

const NilVersion = nilVersion

// TestClearEditions is a test helper to reset the editions map.
func TestClearEditions(t *testing.T) {
	t.Helper()
	editions.Lock()
	defer editions.Unlock()

	editions.m = make(map[edition.Dialect]edition.Editions)
}
