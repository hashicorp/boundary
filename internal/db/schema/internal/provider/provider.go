// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package provider provides an iterator for iterating over all of the
// migration statements that need to be applied. It will provide the statements
// in the correct order based on the Edition priority and migration version.
package provider

import (
	"sort"

	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
)

const nilVersion = -1

// Provider provides the migrations to the schema.Manager in the correct order.
type Provider struct {
	pos        int
	migrations []migration.Migration
}

// DatabaseState is a map of edition names to versions.
type DatabaseState map[string]int

// New creates a Provider. The given DatabaseState is compared against the editions
// to determine which migrations need to be applied and the migrations are then ordered
// based on the Edition priority and by the migration version.
func New(dbState DatabaseState, editions edition.Editions) *Provider {
	m := &Provider{
		pos: -1,
	}

	// ensure editions in priority order
	editions.Sort()

	allMigrations := make([]migration.Migration, 0)

	for _, e := range editions {
		dbVer, ok := dbState[e.Name]
		if !ok {
			dbVer = nilVersion
		}

		migrations := make([]migration.Migration, 0, len(e.Migrations))
		for ver, m := range e.Migrations {
			if ver > dbVer {
				migrations = append(migrations, m)
			}
		}

		sort.SliceStable(migrations, func(i, j int) bool {
			return migrations[i].Version < migrations[j].Version
		})

		allMigrations = append(allMigrations, migrations...)
	}

	m.migrations = allMigrations

	return m
}

// Next proceeds to the next migration. It returns true on success or false
// if there are no more migrations.
func (p *Provider) Next() bool {
	p.pos++
	return len(p.migrations) > p.pos
}

// Version returns the version for the current migration.
func (p *Provider) Version() int {
	if p.pos < 0 || p.pos >= len(p.migrations) {
		return -1
	}
	return p.migrations[p.pos].Version
}

// Edition returns the edition name for the current migration.
func (p *Provider) Edition() string {
	if p.pos < 0 || p.pos >= len(p.migrations) {
		return ""
	}
	return p.migrations[p.pos].Edition
}

// Statements returns the sql statements name for the current migration.
func (p *Provider) Statements() []byte {
	if p.pos < 0 || p.pos >= len(p.migrations) {
		return nil
	}
	return p.migrations[p.pos].Statements
}

// PreHook returns the hooks that should be run prior to the current migration.
func (p *Provider) PreHook() *migration.Hook {
	if p.pos < 0 || p.pos >= len(p.migrations) {
		return nil
	}
	return p.migrations[p.pos].PreHook
}
