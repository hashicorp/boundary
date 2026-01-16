// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema

import (
	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

// PartialEditions is used by TestCreatePartialEditions. It is a map of edition
// names to the max version that should be included.
type PartialEditions map[string]int

// TestCreatePartialEditions is used by tests to create a subset of the Edition migrations.
func TestCreatePartialEditions(dialect Dialect, p PartialEditions) edition.Editions {
	editions.Lock()
	defer editions.Unlock()

	e := make(edition.Editions, 0, len(p))
	for _, ee := range editions.m[dialect] {
		maxVer, ok := p[ee.Name]
		if ok {
			edition := edition.Edition{
				Name:          ee.Name,
				Dialect:       ee.Dialect,
				Priority:      ee.Priority,
				LatestVersion: nilVersion,
				Migrations:    make(migration.Migrations),
			}

			for k, b := range ee.Migrations {
				if k > maxVer {
					continue
				}

				edition.Migrations[k] = b
				if k > edition.LatestVersion {
					edition.LatestVersion = k
				}
			}
			e = append(e, edition)
		}
	}

	return e
}
